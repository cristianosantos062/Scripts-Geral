USE [master]
GO

DECLARE @custompath NVARCHAR(500), @allow_xpcmdshell bit

/* READ ME
Default location for .ps1 files is the Log folder. 
Optionaly, uncomment @custompath below and set the custom desired path.
*/
--SET @custompath = 'C:\<temp_location>'

/* READ ME
Set @allow_xpcmdshell to OFF if you want to skip checks that are dependant on xp_cmdshell.
Note that original server setting for xp_cmdshell would be left unchanged if tests were allowed.
*/
SET @allow_xpcmdshell = 1 --(1 = ON; 0 = OFF)

/*		
Best Practices Check - PTO Clinic Edition - pedro.lopes@microsoft.com (http://toolbox/BPCheck)

DESCRIPTION: This script checks for skews in the most common best practices from SQL Server 2005 onwards.

DISCLAIMER:
This code is not supported under any Microsoft standard support program or service.
This code and information are provided "AS IS" without warranty of any kind, either expressed or implied.
The entire risk arising out of the use or performance of the script and documentation remains with you. 
Furthermore, Microsoft or the author shall not be liable for any damages you may sustain by using this information, whether direct, 
indirect, special, incidental or consequential, including, without limitation, damages for loss of business profits, business interruption, loss of business information 
or other pecuniary losseven if it has been advised of the possibility of such damages.
Read all the implementation and usage notes thoroughly.

v1 - 21-09-2013 - Initial release of BPCheck - PTOClinic edition, based on BPCheck v1.7.8.
							
PURPOSE: Checks SQL Server in scope for some of most common skewed Best Practices. Valid from SQL Server 2005 onwards.

	- Contains the following information:
	 |- Uptime
	 |- Windows OS info
	 |- HA info
	 |- Linked servers info
	 |- Instance info
	 |- Databases info
	 |- Enterprise features usage
	 |- System configurations
	 |- Backups info

	- And performs the following checks:
		|- Backup checks (No full backup; No log backup since last full or diff; Last log backup older than 24H)
		|- Number of available Processors for this instance vs. MaxDOP setting
		|- Processor Affinity in NUMA architecture
		|- Additional Processor information
		|- Processor utilization rate in the last 2 hours
		|- Server Memory
		|- Pagefile
		|- Power plan
		|- Global trace flags
		|- System configurations
		|- IFI
		|- LPIM
		|- DBs with collation <> master
		|- DBs with skewed compatibility level
		|- User DBs with non-default options
		|- DBs Autogrow in percentage
		|- DBs Autogrowth > 1GB in Logs or Data (when IFI is disabled)
		|- Data files and Logs / tempDB and user Databases in same volume (Mountpoint aware)
		|- All tempDB files are of equal size and even number
		|- tempDB Files autogrow of equal size
		|- NTFS block size in volumes that hold database files <> 64KB
		|- VLF
		|- Perf counters, Waits and Latches (wait for 90s)
		|- Worker thread exhaustion
		|- Plan use ratio
		|- Hints usage
		|- Cached Query Plans issues
		|- Deprecated features
		|- Statistics update
		|- Hypothetical objects
		|- Duplicate or Redundant indexes (Clustered, Non-Clustered, Clustered and Non-Clustered Columnstore IXs only)
		|- Unused and rarely used indexes
		|- Indexes with large keys (> 900 bytes)
		|- Indexes with fill factor < 80 pct
		|- Disabled indexes
		|- Non-unique clustered indexes
		|- Foreign Keys with no Index
		|- Indexing per Table (No IXs; No Clustered IX; More IXs than Cols; Misaligned IXs)
		|- Missing Indexes (most relevant ones, score based)
		|- DBCC CHECKDB, Direct Catalog Updates and Data Purity
		|- AlwaysOn/Mirroring automatic page repair
		|- Suspect pages
		|- I/O Stall in excess of 50% or high latencies in database files
		|- Errorlog based checks

DISCLAIMER:
This code and information are provided "AS IS" without warranty of any kind, either expressed or implied.
Furthermore, the author or Ezequiel shall not be liable for any damages you may sustain by using this information, whether direct, indirect, special, incidental or consequential, even if it has been advised of the possibility of such damages.
			
IMPORTANT pre-requisites:
- Only a sysadmin/local host admin will be able to perform all checks.
- If you want to perform all checks under non-sysadmin credentials, then that login must be:
	Member of serveradmin server role or have the ALTER SETTINGS server permission; 
	Member of MSDB SQLAgentOperatorRole role, or have SELECT permission on the sysalerts table in MSDB;
	Granted EXECUTE permissions on the following extended sprocs to run checks: sp_OACreate, sp_OADestroy, sp_OAGetErrorInfo, xp_enumerrorlogs, xp_fileexist and xp_regenumvalues;
	Granted EXECUTE permissions on xp_msver;
	Granted the VIEW SERVER STATE permission;
	Granted EXECUTE permissions on xp_cmdshell or a xp_cmdshell proxy account should exist to run checks that access disk or OS security configurations.
	Member of securityadmin role, or have EXECUTE permissions on sp_readerrorlog. 
 Otherwise some checks will be bypassed and warnings will be shown.
- Powershell must be installed to run checks that access disk configurations, as well as allow execution of unsigned scripts.
*/

SET NOCOUNT ON;
SET ANSI_WARNINGS ON;
SET QUOTED_IDENTIFIER ON;
SET DATEFORMAT mdy;

RAISERROR (N'Starting Pre-requisites section', 10, 1) WITH NOWAIT

--------------------------------------------------------------------------------------------------------------------------------
-- Pre-requisites section
--------------------------------------------------------------------------------------------------------------------------------
DECLARE @sqlcmd NVARCHAR(4000), @params NVARCHAR(500), @sqlmajorver int

SELECT @sqlmajorver = CONVERT(int, (@@microsoftversion / 0x1000000) & 0xff);

IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 0)
BEGIN
	RAISERROR('[WARNING: Only a sysadmin can run ALL the checks]', 16, 1, N'sysadmin')
	--RETURN
END;

IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 0)
BEGIN
	DECLARE @pid int, @pname sysname, @msdbpid int, @masterpid int
	DECLARE @permstbl TABLE ([name] sysname);
	DECLARE @permstbl_msdb TABLE ([id] tinyint IDENTITY(1,1), [perm] tinyint)
	
	SET @params = '@msdbpid_in int'

	SELECT @pid = principal_id, @pname=name FROM master.sys.server_principals (NOLOCK) WHERE sid = SUSER_SID()

	SELECT @masterpid = principal_id FROM master.sys.database_principals (NOLOCK) WHERE sid = SUSER_SID()

	SELECT @msdbpid = principal_id FROM msdb.sys.database_principals (NOLOCK) WHERE sid = SUSER_SID()

	-- Perms 1
	IF (ISNULL(IS_SRVROLEMEMBER(N'serveradmin'), 0) <> 1) AND ((SELECT COUNT(l.name)
		FROM master.sys.server_permissions p (NOLOCK) INNER JOIN master.sys.server_principals l (NOLOCK)
		ON p.grantee_principal_id = l.principal_id
			AND p.class = 100 -- Server
			AND p.state IN ('G', 'W') -- Granted or Granted with Grant
			AND l.is_disabled = 0
			AND p.permission_name = 'ALTER SETTINGS'
			AND QUOTENAME(l.name) = QUOTENAME(@pname)) = 0)
	BEGIN
		RAISERROR('[WARNING: If not sysadmin, then you must be a member of serveradmin server role or have the ALTER SETTINGS server permission]', 16, 1, N'serveradmin')
		RETURN
	END
	ELSE IF (ISNULL(IS_SRVROLEMEMBER(N'serveradmin'), 0) <> 1) AND ((SELECT COUNT(l.name)
		FROM master.sys.server_permissions p (NOLOCK) INNER JOIN sys.server_principals l (NOLOCK)
		ON p.grantee_principal_id = l.principal_id
			AND p.class = 100 -- Server
			AND p.state IN ('G', 'W') -- Granted or Granted with Grant
			AND l.is_disabled = 0
			AND p.permission_name = 'VIEW SERVER STATE'
			AND QUOTENAME(l.name) = QUOTENAME(@pname)) = 0)
	BEGIN
		RAISERROR('[WARNING: If not sysadmin, then you must be a member of serveradmin server role or granted the VIEW SERVER STATE permission]', 16, 1, N'serveradmin')
		RETURN
	END

	-- Perms 2
	INSERT INTO @permstbl
	SELECT a.name
	FROM master.sys.all_objects a (NOLOCK) INNER JOIN master.sys.database_permissions b (NOLOCK) ON a.[OBJECT_ID] = b.major_id
	WHERE a.type IN ('P', 'X') AND b.grantee_principal_id <>0 
	AND b.grantee_principal_id <>2
	AND b.grantee_principal_id = @masterpid;

	INSERT INTO @permstbl_msdb ([perm])
	EXEC sp_executesql N'USE msdb; SELECT COUNT([name]) 
FROM msdb.sys.sysusers (NOLOCK) WHERE [uid] IN (SELECT [groupuid] 
	FROM msdb.sys.sysmembers (NOLOCK) WHERE [memberuid] = @msdbpid_in) 
AND [name] = ''SQLAgentOperatorRole''', @params, @msdbpid_in = @msdbpid;

	INSERT INTO @permstbl_msdb ([perm])
	EXEC sp_executesql N'USE msdb; SELECT COUNT(dp.grantee_principal_id)
FROM msdb.sys.tables AS tbl (NOLOCK)
INNER JOIN msdb.sys.database_permissions AS dp (NOLOCK) ON dp.major_id=tbl.object_id AND dp.class=1
INNER JOIN msdb.sys.database_principals AS grantor_principal (NOLOCK) ON grantor_principal.principal_id = dp.grantor_principal_id
INNER JOIN msdb.sys.database_principals AS grantee_principal (NOLOCK) ON grantee_principal.principal_id = dp.grantee_principal_id
WHERE dp.state = ''G''
	AND dp.grantee_principal_id = @msdbpid_in
	AND dp.type = ''SL''', @params, @msdbpid_in = @msdbpid;

	IF (SELECT [perm] FROM @permstbl_msdb WHERE [id] = 1) = 0 AND (SELECT [perm] FROM @permstbl_msdb WHERE [id] = 2) = 0
	BEGIN
		RAISERROR('[WARNING: If not sysadmin, then you must be a member of MSDB SQLAgentOperatorRole role, or have SELECT permission on the sysalerts table in MSDB to run full scope of checks]', 16, 1, N'msdbperms')
		--RETURN
	END
	ELSE IF (ISNULL(IS_SRVROLEMEMBER(N'securityadmin'), 0) <> 1) AND ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_enumerrorlogs') = 0 OR (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_readerrorlog') = 0 OR (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_readerrorlog') = 0)
	BEGIN
		RAISERROR('[WARNING: If not sysadmin, then you must be a member of the securityadmin server role, or have EXECUTE permission on the following extended sprocs to run full scope of checks: xp_enumerrorlogs, xp_readerrorlog, sp_readerrorlog]', 16, 1, N'secperms')
		--RETURN
	END
	ELSE IF (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_cmdshell') = 0 OR (SELECT COUNT(credential_id) FROM master.sys.credentials WHERE name = '##xp_cmdshell_proxy_account##') = 0
	BEGIN
		RAISERROR('[WARNING: If not sysadmin, then you must be granted EXECUTE permissions on xp_cmdshell and a xp_cmdshell proxy account should exist to run full scope of checks]', 16, 1, N'xp_cmdshellproxy')
		--RETURN
	END
	ELSE IF (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_fileexist') = 0 OR
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OAGetErrorInfo') = 0 OR
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OACreate') = 0 OR
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OADestroy') = 0 OR
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regenumvalues') = 0 OR
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') = 0 OR 
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_instance_regread') = 0 OR
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_servicecontrol') = 0 
	BEGIN
		RAISERROR('[WARNING: Must be a granted EXECUTE permissions on the following extended sprocs to run full scope of checks: sp_OACreate, sp_OADestroy, sp_OAGetErrorInfo, xp_fileexist, xp_regread, xp_instance_regread, xp_servicecontrol and xp_regenumvalues]', 16, 1, N'extended_sprocs')
		--RETURN
	END
	ELSE IF (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_msver') = 0 AND @sqlmajorver < 11
	BEGIN
		RAISERROR('[WARNING: Must be granted EXECUTE permissions on xp_msver to run full scope of checks]', 16, 1, N'extended_sprocs')
		--RETURN
	END
END

-- Declare Global Variables
DECLARE @UpTime VARCHAR(12),@StartDate DATETIME
DECLARE @agt smallint, @ole smallint, @sao smallint, @xcmd smallint
DECLARE @ErrorSeverity int, @ErrorState int, @ErrorMessage NVARCHAR(4000)
DECLARE @CMD NVARCHAR(4000)
DECLARE @path NVARCHAR(2048)
DECLARE @sqlminorver int, @sqlbuild int, @clustered bit, @winver VARCHAR(5), @server VARCHAR(128), @instancename NVARCHAR(128), @arch smallint, @winsp VARCHAR(25)
DECLARE @existout int, @FSO int, @FS int, @OLEResult int, @FileID int
DECLARE @FileName VARCHAR(100), @Text1 VARCHAR(300), @CMD2 VARCHAR(100)
DECLARE @src VARCHAR(255), @desc VARCHAR(255)

SELECT @instancename = CONVERT(VARCHAR(128),SERVERPROPERTY('InstanceName')) 
SELECT @server = RTRIM(CONVERT(VARCHAR(128), SERVERPROPERTY('MachineName')))
--SELECT @sqlmajorver = CONVERT(int, (@@microsoftversion / 0x1000000) & 0xff);
SELECT @sqlminorver = CONVERT(int, (@@microsoftversion / 0x10000) & 0xff);
SELECT @sqlbuild = CONVERT(int, @@microsoftversion & 0xffff);
SELECT @clustered = CONVERT(bit,ISNULL(SERVERPROPERTY('IsClustered'),0))

--------------------------------------------------------------------------------------------------------------------------------
-- Information section
--------------------------------------------------------------------------------------------------------------------------------

RAISERROR (N'Starting Information section', 10, 1) WITH NOWAIT

--------------------------------------------------------------------------------------------------------------------------------
-- Uptime subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Uptime subsection', 10, 1) WITH NOWAIT
IF @sqlmajorver < 10
BEGIN
	SET @sqlcmd = N'SELECT @UpTimeOUT = DATEDIFF(mi, login_time, GETDATE()), @StartDateOUT = login_time FROM master..sysprocesses (NOLOCK) WHERE spid = 1';
END
ELSE
BEGIN
	SET @sqlcmd = N'SELECT @UpTimeOUT = DATEDIFF(mi,sqlserver_start_time,GETDATE()), @StartDateOUT = sqlserver_start_time FROM sys.dm_os_sys_info (NOLOCK)';
END

SET @params = N'@UpTimeOUT VARCHAR(12) OUTPUT, @StartDateOUT DATETIME OUTPUT';

EXECUTE sp_executesql @sqlcmd, @params, @UpTimeOUT=@UpTime OUTPUT, @StartDateOUT=@StartDate OUTPUT;

SELECT 'Uptime_Information' AS [Information], GETDATE() AS [Current_Time], @StartDate AS Last_Startup, CONVERT(VARCHAR(4),@UpTime/60/24) + ' d ' + CONVERT(VARCHAR(4),@UpTime/60%24) + ' hr ' + CONVERT(VARCHAR(4),@UpTime%60) + ' min' AS Uptime

--------------------------------------------------------------------------------------------------------------------------------
-- Windows Version and Architecture subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Windows Version and Architecture subsection', 10, 1) WITH NOWAIT
IF @sqlmajorver >= 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500)
BEGIN
	SET @sqlcmd = N'SELECT @winverOUT = windows_release, @winspOUT = windows_service_pack_level, @archOUT = CASE WHEN @@VERSION LIKE ''%<X64>%'' THEN 64 WHEN @@VERSION LIKE ''%<IA64>%'' THEN 128 ELSE 32 END FROM sys.dm_os_windows_info (NOLOCK)';
	SET @params = N'@winverOUT VARCHAR(5) OUTPUT, @winspOUT VARCHAR(25) OUTPUT, @archOUT smallint OUTPUT';
	EXECUTE sp_executesql @sqlcmd, @params, @winverOUT=@winver OUTPUT, @winspOUT=@winsp OUTPUT, @archOUT=@arch OUTPUT;
END
ELSE
BEGIN
	BEGIN TRY
		DECLARE @str VARCHAR(500), @str2 VARCHAR(500), @str3 VARCHAR(500)
		DECLARE @sysinfo TABLE (id int, 
			[Name] NVARCHAR(256), 
			Internal_Value bigint, 
			Character_Value NVARCHAR(256))
		INSERT INTO @sysinfo
		EXEC xp_msver;
		SELECT @winver = LEFT(Character_Value, CHARINDEX(' ', Character_Value)-1) -- 5.2 is WS2003; 6.0 is WS2008; 6.1 is WS2008R2; 6.2 is WS2012
		FROM @sysinfo
		WHERE [Name] LIKE 'WindowsVersion%'
		SELECT @arch = CASE WHEN RTRIM(Character_Value) LIKE '%x64%' OR RTRIM(Character_Value) LIKE '%AMD64%' THEN 64
			WHEN RTRIM(Character_Value) LIKE '%x86%' OR RTRIM(Character_Value) LIKE '%32%' THEN 32
			WHEN RTRIM(Character_Value) LIKE '%IA64%' THEN 128 END
		FROM @sysinfo
		WHERE [Name] LIKE 'Platform%';
		SET @str = (SELECT @@VERSION)
		SELECT @str2 = RIGHT(@str, LEN(@str)-CHARINDEX('Windows',@str) + 1)
		SELECT @str3 = RIGHT(@str2, LEN(@str2)-CHARINDEX(': ',@str2))
		SELECT @winsp = LTRIM(LEFT(@str3, CHARINDEX(')',@str3) -1))
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Windows Version and Architecture subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
END

SELECT 'Machine_Information' AS [Information], 
	CASE @winver WHEN '5.2' THEN 'XP/WS2003' 
		WHEN '6.0' THEN 'Vista/WS2008' 
		WHEN '6.1' THEN 'W7/WS2008R2'
		WHEN '6.2' THEN 'W8/WS2012' END AS [Windows_Version],
	@winsp AS [Service_Pack_Level],
	@arch AS [Architecture],
	SERVERPROPERTY('MachineName') AS [Machine_Name],
	SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS [NetBIOS_Name];
	
--------------------------------------------------------------------------------------------------------------------------------
-- HA Information subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting HA Information subsection', 10, 1) WITH NOWAIT
IF @clustered = 1
BEGIN
	IF @sqlmajorver < 11
		BEGIN
			EXEC ('SELECT ''Cluster_Information'' AS [Information], NodeName AS node_name FROM sys.dm_os_cluster_nodes (NOLOCK)')
		END
	ELSE 
		BEGIN
			EXEC ('SELECT ''Cluster_Information'' AS [Information], NodeName AS node_name, status_description, is_current_owner FROM sys.dm_os_cluster_nodes (NOLOCK)')
		END
	SELECT 'Cluster_Information' AS [Information], DriveName AS cluster_shared_drives FROM sys.dm_io_cluster_shared_drives (NOLOCK)
END
ELSE
BEGIN
	SELECT 'Cluster_Information' AS [Information], 'NOT_CLUSTERED' AS [Status]
END;

IF @sqlmajorver > 10
BEGIN
	DECLARE @IsHadrEnabled tinyint, @HadrManagerStatus tinyint
	SELECT @IsHadrEnabled = CONVERT(tinyint, SERVERPROPERTY('IsHadrEnabled'))
	SELECT @HadrManagerStatus = CONVERT(tinyint, SERVERPROPERTY('HadrManagerStatus'))

	SELECT 'AlwaysOn_AG_Information' AS [Information], 
		CASE @IsHadrEnabled WHEN 0 THEN 'Disabled'
			WHEN 1 THEN 'Enabled' END AS [AlwaysOn_Availability_Groups],
		CASE WHEN @IsHadrEnabled = 1 THEN
			CASE @HadrManagerStatus WHEN 0 THEN 'Not started, pending communication.'
				WHEN 1 THEN 'Started and running.'
				WHEN 2 THEN 'Not started and failed.'
			END
		END AS [Status]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Linked servers info subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Linked servers info subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(*) FROM sys.servers AS s INNER JOIN sys.linked_logins AS l (NOLOCK) ON s.server_id = l.server_id INNER JOIN sys.server_principals AS p (NOLOCK) ON p.principal_id = l.local_principal_id WHERE s.is_linked = 1) > 0
BEGIN
	IF @sqlmajorver > 9
	BEGIN
		EXEC ('SELECT ''Linked_servers_Information'' AS [Information], s.name, s.product, 
	s.provider, s.data_source, s.location, s.provider_string, s.catalog, s.connect_timeout, 
	s.query_timeout, s.is_linked, s.is_remote_login_enabled, s.is_rpc_out_enabled, 
	s.is_data_access_enabled, s.is_collation_compatible, s.uses_remote_collation, s.collation_name, 
	s.lazy_schema_validation, s.is_system, s.is_publisher, s.is_subscriber, s.is_distributor, 
	s.is_nonsql_subscriber, s.is_remote_proc_transaction_promotion_enabled, 
	s.modify_date, CASE WHEN l.local_principal_id = 0 THEN ''local or wildcard'' ELSE p.name END AS [local_principal], 
	CASE WHEN l.uses_self_credential = 0 THEN ''use own credentials'' ELSE ''use supplied username and pwd'' END AS uses_self_credential, 
	l.remote_name, l.modify_date AS [linked_login_modify_date]
FROM sys.servers AS s (NOLOCK)
INNER JOIN sys.linked_logins AS l (NOLOCK) ON s.server_id = l.server_id
INNER JOIN sys.server_principals AS p (NOLOCK) ON p.principal_id = l.local_principal_id
WHERE s.is_linked = 1')
	END
	ELSE 
	BEGIN
		EXEC ('SELECT ''Linked_servers_Information'' AS [Information], s.name, s.product, 
	s.provider, s.data_source, s.location, s.provider_string, s.catalog, s.connect_timeout, 
	s.query_timeout, s.is_linked, s.is_remote_login_enabled, s.is_rpc_out_enabled, 
	s.is_data_access_enabled, s.is_collation_compatible, s.uses_remote_collation, s.collation_name, 
	s.lazy_schema_validation, s.is_system, s.is_publisher, s.is_subscriber, s.is_distributor, 
	s.is_nonsql_subscriber, s.modify_date, CASE WHEN l.local_principal_id = 0 THEN ''local or wildcard'' ELSE p.name END AS [local_principal], 
	CASE WHEN l.uses_self_credential = 0 THEN ''use own credentials'' ELSE ''use supplied username and pwd'' END AS uses_self_credential, 
	l.remote_name, l.modify_date AS [linked_login_modify_date]
FROM sys.servers AS s (NOLOCK)
INNER JOIN sys.linked_logins AS l (NOLOCK) ON s.server_id = l.server_id
INNER JOIN sys.server_principals AS p (NOLOCK) ON p.principal_id = l.local_principal_id
WHERE s.is_linked = 1')
	END
END
ELSE
BEGIN
	SELECT 'Linked_servers_Information' AS [Information], 'None' AS [Status]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Instance info subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Instance info subsection', 10, 1) WITH NOWAIT
DECLARE @port VARCHAR(5), @replication int, @RegKey NVARCHAR(255), @cpuaffin VARCHAR(255), @cpucount int, @numa int
DECLARE @i int, @cpuaffin_fixed VARCHAR(300)

IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500)
BEGIN
	IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1) OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') = 1)
	BEGIN
		BEGIN TRY
			SELECT @RegKey = CASE WHEN CONVERT(VARCHAR(128), SERVERPROPERTY('InstanceName')) IS NULL THEN N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib\Tcp'
				ELSE N'Software\Microsoft\Microsoft SQL Server\' + CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128)) + N'\MSSQLServer\SuperSocketNetLib\Tcp' END
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @RegKey, N'TcpPort', @port OUTPUT, NO_OUTPUT
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Instance info subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
	END
	ELSE
	BEGIN
		RAISERROR('[WARNING: Missing permissions for full "Instance info" checks. Bypassing TCP port check]', 16, 1, N'sysadmin')
		--RETURN
	END
END
ELSE
BEGIN
	BEGIN TRY
		SET @sqlcmd = N'SELECT @portOUT = MAX(CONVERT(int,CONVERT(float,value_data))) FROM sys.dm_server_registry WHERE registry_key LIKE ''%MSSQLServer\SuperSocketNetLib\Tcp\%'' AND value_name LIKE N''%TcpPort%'' AND CONVERT(float,value_data) > 0;';
		SET @params = N'@portOUT int OUTPUT';
		EXECUTE sp_executesql @sqlcmd, @params, @portOUT = @port OUTPUT;
		IF @port IS NULL
		BEGIN
			SET @sqlcmd = N'SELECT @portOUT = CONVERT(int,CONVERT(float,value_data)) FROM sys.dm_server_registry WHERE registry_key LIKE ''%MSSQLServer\SuperSocketNetLib\Tcp\%'' AND value_name LIKE N''%TcpDynamicPort%'' AND CONVERT(float,value_data) > 0;';
			SET @params = N'@portOUT int OUTPUT';
			EXECUTE sp_executesql @sqlcmd, @params, @portOUT = @port OUTPUT;
		END
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Instance info subsection - Error raised in TRY block 2. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
END

IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1) OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_instance_regread') = 1)
BEGIN
	BEGIN TRY
		EXEC master..xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\MSSQLServer\Replication', N'IsInstalled', @replication OUTPUT, NO_OUTPUT
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Instance info subsection - Error raised in TRY block 3. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
END
ELSE
BEGIN
	RAISERROR('[WARNING: Missing permissions for full "Instance info" checks. Bypassing replication check]', 16, 1, N'sysadmin')
	--RETURN
END

SELECT @cpucount = COUNT(cpu_id) FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64
SELECT @numa = COUNT(DISTINCT parent_node_id) FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64;

;WITH bits AS 
(SELECT 7 AS N, 128 AS E UNION ALL SELECT 6, 64 UNION ALL 
SELECT 5, 32 UNION ALL SELECT 4, 16 UNION ALL SELECT 3, 8 UNION ALL 
SELECT 2, 4 UNION ALL SELECT 1, 2 UNION ALL SELECT 0, 1), 
bytes AS 
(SELECT 1 M UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL 
SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL 
SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)
-- CPU Affinity is shown highest to lowest CPU ID
SELECT @cpuaffin = CASE WHEN [value] = 0 THEN REPLICATE('1', @cpucount)
	ELSE RIGHT((SELECT RIGHT(((CONVERT(tinyint, SUBSTRING(CONVERT(binary(9), [value]), M, 1)) & E ) / E),16) AS [text()] 
		FROM bits CROSS JOIN bytes
		ORDER BY M, N DESC
		FOR XML PATH('')), (SELECT COUNT(DISTINCT cpu_id) FROM sys.dm_os_schedulers)) END
FROM sys.configurations (NOLOCK)
WHERE name = 'affinity mask';

SET @cpuaffin_fixed = @cpuaffin

IF @numa > 1
BEGIN
	-- format binary mask by node for better reading
	SET @i = @cpucount/@numa + 1
	WHILE @i <= @cpucount
	BEGIN
		SELECT @cpuaffin_fixed = STUFF(@cpuaffin_fixed, @i, 1, '_' + SUBSTRING(@cpuaffin, @i, 1))
		SET @i = @i + @cpucount/@numa + 1
	END
END

SELECT 'Instance_Information' AS [Information],
	(CASE WHEN CONVERT(VARCHAR(128), SERVERPROPERTY('InstanceName')) IS NULL THEN 'DEFAULT_INSTANCE'
		ELSE CONVERT(VARCHAR(128), SERVERPROPERTY('InstanceName')) END) AS Instance_Name,
	(CASE WHEN SERVERPROPERTY('IsClustered') = 1 THEN 'CLUSTERED' 
		WHEN SERVERPROPERTY('IsClustered') = 0 THEN 'NOT_CLUSTERED'
		ELSE 'INVALID INPUT/ERROR' END) AS Failover_Clustered,
	/*The version of SQL Server instance in the form: major.minor.build*/	
	CONVERT(VARCHAR(128), SERVERPROPERTY('ProductVersion')) AS Product_Version,
	/*Level of the version of SQL Server Instance*/
	CONVERT(VARCHAR(128), SERVERPROPERTY('ProductLevel')) AS Product_Level,
	CONVERT(VARCHAR(128), SERVERPROPERTY('Edition')) AS Edition,
	CONVERT(VARCHAR(128), SERVERPROPERTY('MachineName')) AS Machine_Name,
	RTRIM(@port) AS TCP_Port,
	@@SERVICENAME AS Service_Name,
	/*To identify which sqlservr.exe belongs to this instance*/
	SERVERPROPERTY('ProcessID') AS Process_ID, 
	CONVERT(VARCHAR(128), SERVERPROPERTY('ServerName')) AS Server_Name,
	@cpuaffin_fixed AS Affinity_Mask_Binary,
	CONVERT(VARCHAR(128), SERVERPROPERTY('Collation')) AS [Server_Collation],
	(CASE WHEN @replication = 1 THEN 'Installed' 
		WHEN @replication = 0 THEN 'Not_Installed' 
		ELSE 'INVALID INPUT/ERROR' END) AS Replication_Components_Installation,
	(CASE WHEN SERVERPROPERTY('IsFullTextInstalled') = 1 THEN 'Installed' 
		WHEN SERVERPROPERTY('IsFulltextInstalled') = 0 THEN 'Not_Installed' 
		ELSE 'INVALID INPUT/ERROR' END) AS Full_Text_Installation,
	(CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 1 THEN 'Integrated_Security' 
		WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 0 THEN 'SQL_Server_Security' 
		ELSE 'INVALID INPUT/ERROR' END) AS [Security],
	(CASE WHEN SERVERPROPERTY('IsSingleUser') = 1 THEN 'Single_User' 
		WHEN SERVERPROPERTY('IsSingleUser') = 0	THEN 'Multi_User' 
		ELSE 'INVALID INPUT/ERROR' END) AS [Single_User],
	(CASE WHEN CONVERT(VARCHAR(128), SERVERPROPERTY('LicenseType')) = 'PER_SEAT' THEN 'Per_Seat_Mode' 
		WHEN CONVERT(VARCHAR(128), SERVERPROPERTY('LicenseType')) = 'PER_PROCESSOR' THEN 'Per_Processor_Mode' 
		ELSE 'Disabled' END) AS License_Type, -- From SQL Server 2008R2 always returns DISABLED.
	CONVERT(NVARCHAR(128), SERVERPROPERTY('BuildClrVersion')) AS CLR_Version,
	CASE WHEN @sqlmajorver >= 10 THEN 
		CASE WHEN SERVERPROPERTY('FilestreamConfiguredLevel') = 0 THEN 'Disabled'
			WHEN SERVERPROPERTY('FilestreamConfiguredLevel') = 1 THEN 'Enabled_for_TSQL'
			ELSE 'Enabled for TSQL and Win32' END
	ELSE 'Not compatible' END AS Filestream_Configured_Level,
	CASE WHEN @sqlmajorver >= 10 THEN 
		CASE WHEN SERVERPROPERTY('FilestreamEffectiveLevel') = 0 THEN 'Disabled'
			WHEN SERVERPROPERTY('FilestreamEffectiveLevel') = 1 THEN 'Enabled_for_TSQL'
			ELSE 'Enabled for TSQL and Win32' END
	ELSE 'Not compatible' END AS Filestream_Effective_Level,
	CASE WHEN @sqlmajorver >= 10 THEN 
		SERVERPROPERTY('FilestreamShareName')
	ELSE 'Not compatible' END AS Filestream_Share_Name;
	
--------------------------------------------------------------------------------------------------------------------------------
-- Database Information subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Database Information subsection', 10, 1) WITH NOWAIT
IF @sqlmajorver < 11
BEGIN
	SET @sqlcmd = N'SELECT ''Database_Information'' AS [Information],
	db.[name] AS [Database_Name], db.[database_id], db.recovery_model_desc AS [Recovery_Model], 
	db.create_date, db.log_reuse_wait_desc AS [Log_Reuse_Wait_Description], 
	ls.cntr_value AS [Log_Size_KB], lu.cntr_value AS [Log_Used_KB],
	CAST(CAST(lu.cntr_value AS FLOAT) / CAST(ls.cntr_value AS FLOAT)AS DECIMAL(18,2)) * 100 AS [Log_Used_pct], 
	db.[compatibility_level] AS [DB_Compatibility_Level], db.collation_name AS [DB_Collation], 
	db.page_verify_option_desc AS [Page_Verify_Option], db.is_auto_create_stats_on, db.is_auto_update_stats_on,
	db.is_auto_update_stats_async_on, db.is_parameterization_forced, 
	db.snapshot_isolation_state_desc, db.is_read_committed_snapshot_on,
	db.is_read_only, db.is_auto_close_on, db.is_auto_shrink_on, ''Not compatible'' AS [Indirect_Checkpoint], db.is_trustworthy_on, db.is_db_chaining_on, db.is_parameterization_forced
FROM master.sys.databases AS db (NOLOCK)
INNER JOIN sys.dm_os_performance_counters AS lu (NOLOCK) ON db.name = lu.instance_name
INNER JOIN sys.dm_os_performance_counters AS ls (NOLOCK) ON db.name = ls.instance_name
WHERE lu.counter_name LIKE N''Log File(s) Used Size (KB)%'' 
	AND ls.counter_name LIKE N''Log File(s) Size (KB)%''
	AND ls.cntr_value > 0 
ORDER BY [Database_Name]	
OPTION (RECOMPILE)'
END
ELSE 
BEGIN
	SET @sqlcmd = N'SELECT ''Database_Information'' AS [Information],
	db.[name] AS [Database_Name], db.[database_id], db.recovery_model_desc AS [Recovery_Model], 
	db.create_date, db.log_reuse_wait_desc AS [Log_Reuse_Wait_Description], 
	ls.cntr_value AS [Log_Size_KB], lu.cntr_value AS [Log_Used_KB],
	CAST(CAST(lu.cntr_value AS FLOAT) / CAST(ls.cntr_value AS FLOAT)AS DECIMAL(18,2)) * 100 AS [Log_Used_pct], 
	db.[compatibility_level] AS [DB_Compatibility_Level], db.collation_name AS [DB_Collation], 
	db.page_verify_option_desc AS [Page_Verify_Option], db.is_auto_create_stats_on, db.is_auto_update_stats_on,
	db.is_auto_update_stats_async_on, db.is_parameterization_forced, 
	db.snapshot_isolation_state_desc, db.is_read_committed_snapshot_on,
	db.is_read_only, db.is_auto_close_on, db.is_auto_shrink_on, db.target_recovery_time_in_seconds AS [Indirect_Checkpoint], db.is_trustworthy_on, db.is_db_chaining_on, db.is_parameterization_forced
FROM master.sys.databases AS db (NOLOCK)
INNER JOIN sys.dm_os_performance_counters AS lu (NOLOCK) ON db.name = lu.instance_name
INNER JOIN sys.dm_os_performance_counters AS ls (NOLOCK) ON db.name = ls.instance_name
WHERE lu.counter_name LIKE N''Log File(s) Used Size (KB)%'' 
	AND ls.counter_name LIKE N''Log File(s) Size (KB)%''
	AND ls.cntr_value > 0 
ORDER BY [Database_Name]	
OPTION (RECOMPILE)'
END

EXECUTE sp_executesql @sqlcmd;

SELECT 'Database_File_Information' AS [Information], DB_NAME(database_id) AS [Database_Name], [file_id], type_desc, data_space_id AS [Filegroup], name, physical_name,
	state_desc, (size * 8) / 1024 AS size_MB, CASE max_size WHEN -1 THEN 'Unlimited' ELSE CONVERT(VARCHAR(10), max_size) END AS max_size,
	CASE WHEN is_percent_growth = 0 THEN CONVERT(VARCHAR(10),((growth * 8) / 1024)) ELSE growth END AS [growth], CASE WHEN is_percent_growth = 1 THEN 'Pct' ELSE 'MB' END AS growth_type,
	is_media_read_only, is_read_only, is_sparse, is_name_reserved
FROM sys.master_files (NOLOCK)
ORDER BY database_id, [file_id];

-- http://support.microsoft.com/kb/2857849
IF @sqlmajorver > 10 AND @IsHadrEnabled = 1
BEGIN
	SELECT 'AlwaysOn_AG_Database_Information' AS [Information], dc.database_name AS [Database_Name], 
	d.synchronization_health_desc, d.synchronization_state_desc, d.database_state_desc
	FROM sys.dm_hadr_database_replica_states d 
	INNER JOIN sys.availability_databases_cluster dc ON d.group_database_id=dc.group_database_id 
	WHERE d.is_local=1
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Enterprise features usage subsection
--------------------------------------------------------------------------------------------------------------------------------
IF @sqlmajorver > 9
BEGIN
	RAISERROR (N'|-Starting Enterprise features usage subsection', 10, 1) WITH NOWAIT
	DECLARE @dbid int, @dbname VARCHAR(1000)/*, @sqlcmd NVARCHAR(4000)*/

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbssku%')
	DROP TABLE #tmpdbssku
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbssku%')
	CREATE TABLE #tmpdbssku (id int IDENTITY(1,1), [dbid] int, [dbname] VARCHAR(1000), isdone bit)

	INSERT INTO #tmpdbssku ([dbid], [dbname], [isdone])
	SELECT database_id, name, 0 FROM master.sys.databases (NOLOCK) WHERE is_read_only = 0 AND state = 0 AND database_id > 4 AND is_distributor = 0;

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblPerSku%')
	DROP TABLE #tblPerSku;
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblPerSku%')
	CREATE TABLE #tblPerSku ([DBName] sysname, [Feature_Name] VARCHAR(100));

	WHILE (SELECT COUNT(id) FROM #tmpdbssku WHERE isdone = 0) > 0
	BEGIN
		SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbssku WHERE isdone = 0
		SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT ''' + @dbname + ''' AS [DBName], feature_name FROM sys.dm_db_persisted_sku_features (NOLOCK);'

		BEGIN TRY
			INSERT INTO #tblPerSku
			EXECUTE sp_executesql @sqlcmd
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Enterprise features usage subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		
		UPDATE #tmpdbssku
		SET isdone = 1
		WHERE dbid = @dbid
	END;

	IF (SELECT COUNT([Feature_Name]) FROM #tblPerSku) > 0
	BEGIN
		SELECT 'Enterprise_features_usage' AS [Check], '[INFORMATION: Some databases are using Enterprise only features]' AS [Deviation]
		SELECT 'Enterprise_features_usage' AS [Information], DBName AS [Database_Name], [Feature_Name]
		FROM #tblPerSku
		ORDER BY 2, 3
	END
	ELSE
	BEGIN
		SELECT 'Enterprise_features_usage' AS [Check], '[NA]' AS [Deviation]
	END
END;

--------------------------------------------------------------------------------------------------------------------------------
-- System Configuration subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting System Configuration subsection', 10, 1) WITH NOWAIT
SELECT 'All_System_Configurations' AS [Information],
	name AS [Name],
	configuration_id AS [Number],
	minimum AS [Minimum],
	maximum AS [Maximum],
	is_dynamic AS [Dynamic],
	is_advanced AS [Advanced],
	value AS [ConfigValue],
	value_in_use AS [RunValue],
	description AS [Description]
FROM sys.configurations (NOLOCK)
ORDER BY name OPTION (RECOMPILE);

--------------------------------------------------------------------------------------------------------------------------------
-- Checks section
--------------------------------------------------------------------------------------------------------------------------------

RAISERROR (N'Starting Checks section', 10, 1) WITH NOWAIT

--------------------------------------------------------------------------------------------------------------------------------
-- Backup checks subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Backup checks subsection', 10, 1) WITH NOWAIT
DECLARE @nolog int, @nobck int, @nolog24h int

-- No Full or Log backups
SELECT @nobck = COUNT(d.name) FROM master.sys.databases d (NOLOCK)
WHERE database_id NOT IN (2, 3)
	AND recovery_model < 3 -- not SIMPLE recovery model
	AND d.name NOT IN (SELECT b.database_name FROM msdb.dbo.backupset b WHERE b.type = 'D') -- Full backup
	AND d.name NOT IN (SELECT b.database_name FROM msdb.dbo.backupset b WHERE b.type = 'L'); -- Log backup

-- No Log since last full backup and DB in Full or Bulk-logged RM
SELECT @nolog = COUNT(database_name) FROM msdb.dbo.backupset b (NOLOCK)
WHERE b.type = 'L' -- Log backup
	AND database_name IN (SELECT name FROM master.sys.databases (NOLOCK)
		WHERE database_id NOT IN (2, 3)
			AND recovery_model < 3) -- not SIMPLE recovery model
GROUP BY [database_name]
HAVING MAX(backup_finish_date) < (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset c (NOLOCK) WHERE c.type IN ('D', 'I') -- Full or Differential backup
								AND c.database_name = b.database_name);

-- No Log since last full or diff backup, older than 24h, and DB in Full ar Bulk-logged RM
SELECT @nolog24h = COUNT(database_name) FROM msdb.dbo.backupset b (NOLOCK)
WHERE b.type = 'L' -- Log backup
	AND backup_finish_date > (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset c (NOLOCK) WHERE c.type IN ('D', 'I') -- Full or Differential backup
								AND c.database_name = b.database_name)
	AND backup_finish_date <= DATEADD(hh, -24, GETDATE()) 
	AND database_name IN (SELECT name FROM master.sys.databases (NOLOCK)
		WHERE database_id NOT IN (2, 3)
			AND recovery_model < 3) -- not SIMPLE recovery model
GROUP BY database_name;

IF @nobck > 0
BEGIN
	SELECT 'No_Full_Backups' AS [Check], '[WARNING: Some databases do not have any Full backups]' AS [Deviation]
	SELECT 'No_Full_Backups' AS [Information], d.name AS [Database_Name] FROM master.sys.databases d (NOLOCK)
	WHERE database_id NOT IN (2, 3)
		AND d.name NOT IN (SELECT b.database_name FROM msdb.dbo.backupset b WHERE b.type = 'D') -- Full backup
		AND d.name NOT IN (SELECT b.database_name FROM msdb.dbo.backupset b WHERE b.type = 'L') -- Log backup
	ORDER BY [Database_Name]
END
ELSE
BEGIN
	SELECT 'No_Full_Backups' AS [Check], '[OK]' AS [Deviation]
END;

IF @nolog > 0
BEGIN
	SELECT 'No_Log_Bcks_since_LstFullorDiff' AS [Check], '[WARNING: Some databases in Full or Bulk-Logged recovery model do not have any corresponding transaction Log backups since the last Full or Differential backup]' AS [Deviation]
	SELECT 'No_Log_Bcks_since_LstFullorDiff' AS [Information], database_name AS [Database_Name] FROM msdb.dbo.backupset b 
	WHERE b.type = 'L' -- Log backup
		AND database_name IN (SELECT name FROM master.sys.databases (NOLOCK)
			WHERE database_id NOT IN (2, 3)
				AND recovery_model < 3) -- not SIMPLE recovery model
	GROUP BY [database_name]
	HAVING MAX(backup_finish_date) < (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset c (NOLOCK) WHERE c.type IN ('D', 'I') -- Full or Differential backup
		AND c.database_name = b.database_name)
	ORDER BY [Database_Name];
END
ELSE
BEGIN
	SELECT 'No_Log_Bcks_since_LstFullorDiff' AS [Check], '[OK]' AS [Deviation]
END;

IF @nolog24h > 0
BEGIN
	SELECT 'Log_Bcks_since_LstFullorDiff_are_older_than_24H' AS [Check], '[WARNING: Some databases in Full or Bulk-Logged recovery model have their latest log backup older than 24H]' AS [Deviation]
	SELECT 'Log_Bcks_since_LstFullorDiff_are_older_than_24H' AS [Information], database_name AS [Database_Name] FROM msdb.dbo.backupset b 
	WHERE b.type = 'L' -- Log backup
		AND backup_finish_date > (SELECT MAX(backup_finish_date) FROM msdb.dbo.backupset c (NOLOCK) WHERE c.type IN ('D', 'I') -- Full or Differential backup
									AND c.database_name = b.database_name)
		AND backup_finish_date <= DATEADD(hh, -24, GETDATE()) 
		AND database_name IN (SELECT name FROM master.sys.databases (NOLOCK)
			WHERE database_id NOT IN (2, 3)
				AND recovery_model < 3) -- not SIMPLE recovery model
	GROUP BY [database_name]
	ORDER BY [database_name];
END
ELSE
BEGIN
	SELECT 'Log_Bcks_since_LstFullorDiff_are_older_than_24H' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Number of available Processors for this instance vs. MaxDOP setting subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Number of available Processors for this instance vs. MaxDOP setting subsection', 10, 1) WITH NOWAIT
DECLARE /*@cpucount int, @numa int, */@numa_affinity int

/*
DECLARE @i int, @cpuaffin_fixed VARCHAR(300)
SET @cpuaffin_fixed = @cpuaffin
SET @i = @cpucount/@numa + 1
WHILE @i <= @cpucount
BEGIN
	SELECT @cpuaffin_fixed = STUFF(@cpuaffin_fixed, @i, 1, '_' + SUBSTRING(@cpuaffin, @i, 1))
	SET @i = @i + @cpucount/@numa + 1
END
*/

SELECT @numa_affinity = COUNT(cpu_id) FROM sys.dm_os_schedulers WHERE is_online = 1 AND scheduler_id < 255 AND parent_node_id < 64;
--SELECT @cpucount = COUNT(cpu_id) FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64
SELECT 'Parallelism_MaxDOP' AS [Check],
	CASE WHEN [value] > @numa_affinity THEN '[WARNING: MaxDOP setting exceeds available processor count (affinity)]'
		WHEN @numa = 1 AND @numa_affinity > 8 AND ([value] = 0 OR [value] > 8) THEN '[WARNING: MaxDOP setting is not recommended for current processor count (affinity)]'
		WHEN @numa > 1 AND ([value] = 0 OR [value] > 8 OR [value] > (@cpucount/@numa)) THEN '[WARNING: MaxDOP setting is not recommended for current NUMA node to processor count (affinity) ratio]'
		ELSE '[OK]'
	END AS [Deviation]
FROM sys.configurations (NOLOCK) WHERE name = 'max degree of parallelism';

SELECT 'Parallelism_MaxDOP' AS [Information], [value] AS [Current_MaxDOP], @cpucount AS [Available_Processors], @numa_affinity AS [Affined_Processors], 
	-- Processor Affinity is shown highest to lowest CPU ID
	@cpuaffin_fixed AS Affinity_Mask_Binary
FROM sys.configurations (NOLOCK) WHERE name = 'max degree of parallelism';	

--------------------------------------------------------------------------------------------------------------------------------
-- Processor Affinity in NUMA architecture subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Processor Affinity in NUMA architecture subsection', 10, 1) WITH NOWAIT
IF @numa > 1
BEGIN
	WITH ncpuCTE (ncpus) AS (SELECT COUNT(cpu_id) AS ncpus from sys.dm_os_schedulers WHERE is_online = 1 AND scheduler_id < 255 AND parent_node_id < 64 GROUP BY parent_node_id, is_online HAVING COUNT(cpu_id) = 1),
	cpuCTE (node, afin) AS (SELECT DISTINCT(parent_node_id), is_online FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64 GROUP BY parent_node_id, is_online)
	SELECT 'Affinity_NUMA' AS [Check],
		CASE WHEN (SELECT COUNT(*) FROM ncpuCTE) > 0 THEN '[WARNING: Current NUMA configuration is not recommended. At least one node has a single assigned CPU]' 
			WHEN (SELECT COUNT(DISTINCT(node)) FROM cpuCTE WHERE afin = 0 AND node NOT IN (SELECT DISTINCT(node) FROM cpuCTE WHERE afin = 1)) > 0 THEN '[WARNING: Current NUMA configuration is not recommended. At least one node does not have assigned CPUs]' 
			ELSE '[OK]' END AS [Deviation]
	FROM sys.dm_os_sys_info (NOLOCK) 
	OPTION (RECOMPILE);
	
	SELECT 'Affinity_NUMA' AS [Information], cpu_count AS [Logical_CPU_Count], 
		(SELECT COUNT(DISTINCT parent_node_id) FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64) AS [NUMA_Nodes],
		-- Processor Affinity is shown highest to lowest CPU ID
		@cpuaffin_fixed AS Affinity_Mask_Binary
	FROM sys.dm_os_sys_info (NOLOCK) 
	OPTION (RECOMPILE);
END
ELSE
BEGIN
	SELECT 'Affinity_NUMA' AS [Check], '[Not_NUMA]' AS [Deviation]
	FROM sys.dm_os_sys_info (NOLOCK)
	OPTION (RECOMPILE);
	
	SELECT 'Affinity_NUMA' AS [Information], cpu_count AS [Logical_CPU_Count],
		cpu_count/hyperthread_ratio AS [CPU_Sockets], 0 AS [NUMA_Nodes],
		-- CPU Affinity is shown highest to lowest CPU ID
		@cpuaffin_fixed AS Affinity_Mask_Binary
	FROM sys.dm_os_sys_info (NOLOCK)
	OPTION (RECOMPILE);
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Additional Processor information subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Additional Processor information subsection', 10, 1) WITH NOWAIT

-- Processor Info
SELECT 'Processor_Summary' AS [Information], cpu_count AS [Logical_CPU_Count], hyperthread_ratio AS [Cores2Socket_Ratio],
	cpu_count/hyperthread_ratio AS [CPU_Sockets], 
	CASE WHEN @numa > 1 THEN (SELECT COUNT(DISTINCT parent_node_id) FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64) ELSE 0 END AS [NUMA_Nodes],
	@numa_affinity AS [Affined_Processors], 
	-- Processor Affinity is shown highest to lowest Processor ID
	@cpuaffin_fixed AS Affinity_Mask_Binary
FROM sys.dm_os_sys_info (NOLOCK)
OPTION (RECOMPILE);

-- Processor utilization rate in the last 2 hours
DECLARE @ts_now bigint
DECLARE @tblAggCPU TABLE (SQLProc tinyint, SysIdle tinyint, OtherProc tinyint, Minutes tinyint)
SELECT @ts_now = ms_ticks FROM sys.dm_os_sys_info (NOLOCK);

WITH cteCPU (record_id, SystemIdle, SQLProcessUtilization, [timestamp]) AS (SELECT 
		record.value('(./Record/@id)[1]', 'int') AS record_id,
		record.value('(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]', 'int') AS SystemIdle,
		record.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS SQLProcessUtilization,
		[TIMESTAMP] FROM (SELECT [TIMESTAMP], CONVERT(xml, record) AS record 
			FROM sys.dm_os_ring_buffers (NOLOCK)
			WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR'
			AND record LIKE '%<SystemHealth>%') AS x
	)
INSERT INTO @tblAggCPU
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 10 
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -10, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 20
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -10, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -20, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 30
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -20, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -30, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 40
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -30, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -40, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 50
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -40, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -50, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 60
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -50, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -60, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 70
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -60, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -70, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 80
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -70, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -80, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 90
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -80, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -90, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 100
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -90, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -100, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 110
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -100, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -110, GETDATE())
UNION ALL 
	SELECT AVG(SQLProcessUtilization), AVG(SystemIdle), 100 - AVG(SystemIdle) - AVG(SQLProcessUtilization), 120
	FROM cteCPU 
	WHERE DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) <= DATEADD(mi, -110, GETDATE()) AND 
		DATEADD(ms, -1 * (@ts_now - [timestamp]), GETDATE()) > DATEADD(mi, -120, GETDATE())

IF (SELECT COUNT(SysIdle) FROM @tblAggCPU WHERE SysIdle < 30) > 0
BEGIN
	SELECT 'Processor_Usage_last_2h' AS [Check], '[WARNING: Detected CPU usage over 70 pct]' AS [Deviation];
END
ELSE IF (SELECT COUNT(SysIdle) FROM @tblAggCPU WHERE SysIdle < 10) > 0
BEGIN
	SELECT 'Processor_Usage_last_2h' AS [Check], '[WARNING: Detected CPU usage over 90 pct]' AS [Deviation];
END
ELSE
BEGIN
	SELECT 'Processor_Usage_last_2h' AS [Check], '[OK]' AS [Deviation];
END;

SELECT 'Agg_Processor_Usage_last_2h' AS [Information], SQLProc AS [SQL_Process_Utilization], SysIdle AS [System_Idle], OtherProc AS [Other_Process_Utilization], Minutes AS [Time_Slice_min]
FROM @tblAggCPU;

--------------------------------------------------------------------------------------------------------------------------------
-- Server Memory subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Server Memory subsection', 10, 1) WITH NOWAIT
DECLARE @maxservermem bigint, @minservermem bigint, @systemmem bigint, @systemfreemem bigint, @numa_nodes_afinned tinyint
DECLARE @commit_target bigint -- Includes stolen and reserved memory in the memory manager
DECLARE @commited bigint -- Does not include reserved memory in the memory manager

IF @sqlmajorver = 9
BEGIN
	SET @sqlcmd = N'SELECT @systemmemOUT = t1.record.value(''(./Record/MemoryRecord/TotalPhysicalMemory)[1]'', ''bigint'')/1024, 
	@systemfreememOUT = t1.record.value(''(./Record/MemoryRecord/AvailablePhysicalMemory)[1]'', ''bigint'')/1024
FROM (SELECT MAX([TIMESTAMP]) AS [TIMESTAMP], CONVERT(xml, record) AS record 
	FROM sys.dm_os_ring_buffers (NOLOCK)
	WHERE ring_buffer_type = N''RING_BUFFER_RESOURCE_MONITOR''
		AND record LIKE ''%RESOURCE_MEMPHYSICAL%''
	GROUP BY record) AS t1';
END
ELSE
BEGIN
	SET @sqlcmd = N'SELECT @systemmemOUT = total_physical_memory_kb/1024, @systemfreememOUT = available_physical_memory_kb/1024 FROM sys.dm_os_sys_memory';
END

SET @params = N'@systemmemOUT bigint OUTPUT, @systemfreememOUT bigint OUTPUT';

EXECUTE sp_executesql @sqlcmd, @params, @systemmemOUT=@systemmem OUTPUT, @systemfreememOUT=@systemfreemem OUTPUT;

IF @sqlmajorver >= 9 AND @sqlmajorver < 11
BEGIN
	SET @sqlcmd = N'SELECT @commit_targetOUT=bpool_commit_target*8, @commitedOUT=bpool_committed*8 FROM sys.dm_os_sys_info (NOLOCK)'
END
ELSE IF @sqlmajorver >= 11
BEGIN
	SET @sqlcmd = N'SELECT @commit_targetOUT=committed_target_kb, @commitedOUT=committed_kb FROM sys.dm_os_sys_info (NOLOCK)'
END

SET @params = N'@commit_targetOUT bigint OUTPUT, @commitedOUT bigint OUTPUT';

EXECUTE sp_executesql @sqlcmd, @params, @commit_targetOUT=@commit_target OUTPUT, @commitedOUT=@commited OUTPUT;

SELECT @minservermem = CONVERT(int, [value]) FROM sys.configurations (NOLOCK) WHERE [Name] = 'min server memory (MB)';
SELECT @maxservermem = CONVERT(int, [value]) FROM sys.configurations (NOLOCK) WHERE [Name] = 'max server memory (MB)';

SELECT @numa_nodes_afinned = COUNT (DISTINCT parent_node_id) FROM sys.dm_os_schedulers WHERE scheduler_id < 255 AND parent_node_id < 64 AND is_online = 1

SELECT 'Memory_issues_MaxServerMem' AS [Check],
	CASE WHEN @maxservermem = 2147483647 THEN '[WARNING: MaxMem setting is default. Please revise memory settings]'
		WHEN @maxservermem > @systemmem THEN '[WARNING: MaxMem setting exceeds available system memory]'
		WHEN @numa > 1 AND (@maxservermem/@numa) * @numa_nodes_afinned > (@systemmem/@numa) * @numa_nodes_afinned THEN '[WARNING: Current MaxMem setting will leverage node foreign memory. 
Maximum value for MaxMem setting on this configuration is ' + CONVERT(NVARCHAR,(@systemmem/@numa) * @numa_nodes_afinned) + ' for a single instance]'
		ELSE '[OK]'
	END AS [Deviation];

SELECT 'Memory_issues_MinServerMem' AS [Check],
	CASE WHEN @minservermem = 0 AND @clustered = 1 THEN '[INFORMATION: Min Server Mem setting is default in a clustered instance. Leverage Min Server Mem for the purpose of limiting memory concurrency between instances]'
		WHEN @minservermem = @maxservermem THEN '[WARNING: Min Server Mem setting is equal to Max Server Mem. This will not allow dynamic memory. Please revise memory settings]'
		WHEN @numa > 1 AND (@minservermem/@numa) * @numa_nodes_afinned > (@systemmem/@numa) * @numa_nodes_afinned THEN '[WARNING: Current MinMem setting will leverage node foreign memory]'
		ELSE '[OK]'
	END AS [Deviation];

SELECT 'Memory_issues_FreeMem' AS [Check],
	CASE WHEN (@systemfreemem*100)/@systemmem <= 5 THEN '[WARNING: Less than 5 percent of Free Memory available. Please revise memory settings]'
		WHEN @systemfreemem <= 150 THEN '[WARNING: System Free Memory is dangerously low. Please revise memory settings]'
		ELSE '[OK]'
	END AS [Deviation];

SELECT 'Memory_issues_CommitedMem' AS [Check],
	CASE WHEN @commit_target > @commited AND @sqlmajorver >= 11 THEN '[INFORMATION: Memory manager will try to obtain additional memory]'
		WHEN @commit_target < @commited AND @sqlmajorver >= 11  THEN '[INFORMATION: Memory manager will try to shrink the amount of memory committed]'
		WHEN @commit_target > @commited AND @sqlmajorver < 11 THEN '[INFORMATION: Buffer Pool will try to obtain additional memory]'
		WHEN @commit_target < @commited AND @sqlmajorver < 11  THEN '[INFORMATION: Buffer Pool will try to shrink]'
		ELSE '[OK]'
	END AS [Deviation];

SELECT 'Memory_reference' AS [Check],
	CASE WHEN @arch IS NULL THEN '[WARNING: Could not determine architecture needed for check]'
		WHEN @arch = 64 AND @systemmem <= 2048 AND @maxservermem > @systemmem-500 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-500) + ' for a single instance]'
		WHEN @arch = 64 AND @systemmem BETWEEN 2049 AND 4096 AND @maxservermem > @systemmem-800 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-800) + ' for a single instance]'
		WHEN @arch = 64 AND @systemmem BETWEEN 4097 AND 8192 AND @maxservermem > @systemmem-1200 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-1200) + ' for a single instance]'
		WHEN @arch = 64 AND @systemmem BETWEEN 8193 AND 12288 AND @maxservermem > @systemmem-2000 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-2000) + ' for a single instance]'
		WHEN @arch = 64 AND @systemmem BETWEEN 12289 AND 24576 AND @maxservermem > @systemmem-2500 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-2500) + ' for a single instance]'
		WHEN @arch = 64 AND @systemmem BETWEEN 24577 AND 32768 AND @maxservermem > @systemmem-3000 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-3000) + ' for a single instance]'
		WHEN @arch = 64 AND @systemmem > 32768 AND @maxservermem > @systemmem-4000 THEN '[WARNING: Recommended MaxMem setting for this configuration is ' + CONVERT(NVARCHAR(20),@systemmem-4000) + ' for a single instance]'
		WHEN @arch = 32 THEN '[INFORMATION: No specific recommendation for referenced architecture]'
		ELSE '[OK]'
	END AS [Deviation];

IF @sqlmajorver = 9
BEGIN
	SELECT 'Memory_Summary' AS [Information], 
		@maxservermem AS sql_max_mem_MB, @minservermem AS sql_min_mem_MB,
		@commit_target/1024 AS sql_commit_target_MB, --BPool in SQL 2005 to 2008R2
		@commited/1024 AS sql_commited_MB, --BPool in SQL 2005 to 2008R2
		@systemmem AS system_total_physical_memory_MB, 
		@systemfreemem AS system_available_physical_memory_MB
END
ELSE
BEGIN
	SET @sqlcmd = N'SELECT ''Memory_Summary'' AS [Information], 
	@maxservermemIN AS sql_max_mem_MB, @minservermemIN AS sql_min_mem_MB, 
	@commit_targetIN/1024 AS sql_commit_target_MB, --BPool in SQL 2005 to 2008R2
	@commitedIN/1024 AS sql_commited_MB, --BPool in SQL 2005 to 2008R2
	physical_memory_in_use_kb/1024 AS sql_physical_memory_in_use_MB, 
	large_page_allocations_kb/1024 AS sql_large_page_allocations_MB, 
	locked_page_allocations_kb/1024 AS sql_locked_page_allocations_MB,	
	@systemmemIN AS system_total_physical_memory_MB, 
	@systemfreememIN AS system_available_physical_memory_MB, 
	total_virtual_address_space_kb/1024 AS sql_total_VAS_MB, 
	virtual_address_space_reserved_kb/1024 AS sql_VAS_reserved_MB, 
	virtual_address_space_committed_kb/1024 AS sql_VAS_committed_MB, 
	virtual_address_space_available_kb/1024 AS sql_VAS_available_MB,
	page_fault_count AS sql_page_fault_count,
	memory_utilization_percentage AS sql_memory_utilization_percentage, 
	process_physical_memory_low AS sql_process_physical_memory_low, 
	process_virtual_memory_low AS sql_process_virtual_memory_low	
FROM sys.dm_os_process_memory (NOLOCK)'
	SET @params = N'@maxservermemIN bigint, @minservermemIN bigint, @systemmemIN bigint, @systemfreememIN bigint, @commit_targetIN bigint, @commitedIN bigint';
	EXECUTE sp_executesql @sqlcmd, @params, @maxservermemIN=@maxservermem, @minservermemIN=@minservermem,@systemmemIN=@systemmem, @systemfreememIN=@systemfreemem, @commit_targetIN=@commit_target, @commitedIN=@commited
END;

SELECT 'Memory_RM_Notifications' AS [Information], 
CASE WHEN x.[TIMESTAMP] BETWEEN -2147483648 AND 2147483647 AND si.ms_ticks BETWEEN -2147483648 AND 2147483647 THEN DATEADD(ms, x.[TIMESTAMP] - si.ms_ticks, GETDATE()) 
	ELSE DATEADD(s, ([TIMESTAMP]/1000) - (si.ms_ticks/1000), GETDATE()) END AS Event_Time,
	record.value('(/Record/ResourceMonitor/Notification)[1]', 'VARCHAR(max)') AS [Notification],
	record.value('(./Record/MemoryRecord/TotalPhysicalMemory)[1]', 'bigint')/1024 AS [Total_Physical_Mem_MB],
	record.value('(/Record/MemoryRecord/AvailablePhysicalMemory)[1]', 'bigint')/1024 AS [Avail_Physical_Mem_MB],
	record.value('(/Record/MemoryRecord/AvailableVirtualAddressSpace)[1]', 'bigint')/1024 AS [Avail_VAS_MB],
	record.value('(./Record/MemoryRecord/TotalPageFile)[1]', 'bigint')/1024 AS [Total_Pagefile_MB],
	record.value('(./Record/MemoryRecord/AvailablePageFile)[1]', 'bigint')/1024 AS [Avail_Pagefile_MB]
FROM (SELECT [TIMESTAMP], CONVERT(xml, record) AS record 
			FROM sys.dm_os_ring_buffers (NOLOCK)
			WHERE ring_buffer_type = N'RING_BUFFER_RESOURCE_MONITOR') AS x
CROSS JOIN sys.dm_os_sys_info si (NOLOCK)
--WHERE CASE WHEN x.[timestamp] BETWEEN -2147483648 AND 2147483648 THEN DATEADD(ms, x.[timestamp] - si.ms_ticks, GETDATE()) 
--	ELSE DATEADD(s, (x.[timestamp]/1000) - (si.ms_ticks/1000), GETDATE()) END >= DATEADD(hh, -12, GETDATE())
;

--------------------------------------------------------------------------------------------------------------------------------
-- Pagefile subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Pagefile subsection', 10, 1) WITH NOWAIT
DECLARE @pf_value tinyint--, @RegKey NVARCHAR(255)
DECLARE @pagefile bigint, @freepagefile bigint
DECLARE @tbl_pf_value TABLE (Value VARCHAR(25), Data VARCHAR(50))

IF @sqlmajorver = 9
BEGIN
	SET @sqlcmd = N'SELECT @pagefileOUT = t1.record.value(''(./Record/MemoryRecord/TotalPageFile)[1]'', ''bigint'')/1024,
	@freepagefileOUT = t1.record.value(''(./Record/MemoryRecord/AvailablePageFile)[1]'', ''bigint'')/1024
FROM (SELECT MAX([TIMESTAMP]) AS [TIMESTAMP], CONVERT(xml, record) AS record 
	FROM sys.dm_os_ring_buffers (NOLOCK)
	WHERE ring_buffer_type = N''RING_BUFFER_RESOURCE_MONITOR''
		AND record LIKE ''%RESOURCE_MEMPHYSICAL%''
	GROUP BY record) AS t1';
END
ELSE
BEGIN
	SET @sqlcmd = N'SELECT @pagefileOUT = total_page_file_kb/1024, @freepagefileOUT = available_page_file_kb/1024 FROM sys.dm_os_sys_memory (NOLOCK)';
END

SET @params = N'@pagefileOUT bigint OUTPUT, @freepagefileOUT bigint OUTPUT';

EXECUTE sp_executesql @sqlcmd, @params, @pagefileOUT=@pagefile OUTPUT, @freepagefileOUT=@freepagefile OUTPUT;

IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1) OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') = 1)
BEGIN
	BEGIN TRY
		SELECT @RegKey = N'System\CurrentControlSet\Control\Session Manager\Memory Management'
		INSERT INTO @tbl_pf_value
		EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @RegKey, N'PagingFiles', NO_OUTPUT
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Pagefile subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
END
ELSE
BEGIN
	RAISERROR('[WARNING: Missing permissions for full "Pagefile" checks. Bypassing System managed pagefile check]', 16, 1, N'sysadmin')
	--RETURN
END;

IF (SELECT COUNT(*) FROM @tbl_pf_value) > 0 
BEGIN
	SELECT @pf_value = CASE WHEN (SELECT COUNT(*) FROM @tbl_pf_value WHERE Data = '') > 0 THEN 1
			WHEN (SELECT COUNT(*) FROM @tbl_pf_value WHERE Data = '?:\pagefile.sys') > 0 THEN 2
			WHEN (SELECT COUNT(*) FROM @tbl_pf_value WHERE Data LIKE '%:\pagefile.sys 0 0%') > 0 THEN 3
		ELSE 0 END
	FROM @tbl_pf_value

	SELECT 'Pagefile_management' AS [Check], 
		CASE WHEN @pf_value = 1 THEN '[WARNING: No pagefile is configured]'
			WHEN @pf_value = 2 THEN '[WARNING: Pagefile is managed automatically on ALL drives]'
			WHEN @pf_value = 3 THEN '[WARNING: Pagefile is managed automatically]'
		ELSE '[OK]' END AS [Deviation]
END

SELECT 'Pagefile_free_space' AS [Check],
	CASE WHEN (@freepagefile*100)/@pagefile <= 10 THEN '[WARNING: Less than 10 percent of Page File is available. Please revise Page File settings]'
		WHEN @freepagefile <= 150 THEN '[WARNING: Page File free space is dangerously low. Please revise Page File settings]'
		ELSE '[OK]' END AS [Deviation], 
	@pagefile AS total_pagefile_MB, @freepagefile AS available_pagefile_MB;

SELECT 'Pagefile_minimum_size' AS [Check],
	CASE WHEN @winver = '5.2' AND @arch = 64 AND @pagefile < 8192 THEN '[WARNING: Page File is smaller than 8GB on a WS2003 x64 system. Please revise Page File settings]'
		WHEN @winver = '5.2' AND @arch = 32 AND @pagefile < 2048 THEN '[WARNING: Page File is smaller than 2GB on a WS2003 x86 system. Please revise Page File settings]'
		WHEN @winver <> '5.2' THEN '[NA]'
		ELSE '[OK]' END AS [Deviation], 
	@pagefile AS total_pagefile_MB;

--------------------------------------------------------------------------------------------------------------------------------
-- Power plan subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Power plan subsection', 10, 1) WITH NOWAIT
DECLARE @planguid NVARCHAR(64), @powerkey NVARCHAR(255) 
--SELECT @powerkey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{025A5937-A6BE-4686-A844-36FE4BEC8B6D}'
--SELECT @powerkey = 'SYSTEM\CurrentControlSet\Control\Power\User\Default\PowerSchemes'
SELECT @powerkey = 'SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'

IF @winver >= 6.0
BEGIN
	BEGIN TRY
		--EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @powerkey, 'PreferredPlan', @planguid OUTPUT, NO_OUTPUT
		EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', @powerkey, 'ActivePowerScheme', @planguid OUTPUT, NO_OUTPUT
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Power plan subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
END

-- http://support.microsoft.com/kb/935799/en-us

IF @winver IS NULL 
BEGIN
	SELECT 'Current_Power_Plan' AS [Check], '[WARNING: Could not determine Windows version for check]' AS [Deviation]
END
ELSE IF @planguid IS NOT NULL AND @planguid <> '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
BEGIN
	SELECT 'Current_Power_Plan' AS [Check], '[WARNING: The current power plan scheme is not recommended for database servers. Please reconfigure for High Performance mode]' AS [Deviation]
	SELECT 'Current_Power_Plan' AS [Information], CASE WHEN @planguid = '381b4222-f694-41f0-9685-ff5bb260df2e' THEN 'Balanced'
		WHEN @planguid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' THEN 'High Performance'
		WHEN @planguid = 'a1841308-3541-4fab-bc81-f71556f20b4a' THEN 'Power Saver'
		ELSE 'Other' END AS [Power_Plan]
END
ELSE IF @planguid IS NOT NULL AND @planguid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
BEGIN
	SELECT 'Current_Power_Plan' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Global trace flags subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Global trace flags subsection', 10, 1) WITH NOWAIT
DECLARE @tracestatus TABLE (TraceFlag NVARCHAR(40), [Status] tinyint, [Global] tinyint, [Session] tinyint);

INSERT INTO @tracestatus 
EXEC ('DBCC TRACESTATUS WITH NO_INFOMSGS')

IF @sqlmajorver >= 11
BEGIN
	DECLARE @dbname0 VARCHAR(1000), @dbid0 int, @sqlcmd0 NVARCHAR(4000), @has_colstrix int

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs0%')
	DROP TABLE #tmpdbs0
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs0%')
	CREATE TABLE #tmpdbs0 (id int IDENTITY(1,1), [dbid] int, [dbname] VARCHAR(1000), isdone bit)

	INSERT INTO #tmpdbs0 ([dbid], [dbname], isdone)
	SELECT database_id, name, 0 FROM master.sys.databases (NOLOCK) WHERE is_read_only = 0 AND state = 0 AND database_id > 4 AND is_distributor = 0;

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblColStoreIXs%')
	DROP TABLE #tblColStoreIXs;
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblColStoreIXs%')
	CREATE TABLE #tblColStoreIXs ([DBName] VARCHAR(1000), [Schema] VARCHAR(100), [Table] VARCHAR(255), [Object] VARCHAR(255));

	WHILE (SELECT COUNT(id) FROM #tmpdbs0 WHERE isdone = 0) > 0
	BEGIN
		SELECT TOP 1 @dbname0 = [dbname], @dbid0 = [dbid] FROM #tmpdbs0 WHERE isdone = 0
		SET @sqlcmd0 = 'USE ' + QUOTENAME(@dbname0) + ';
SELECT ''' + @dbname0 + ''' AS [DBName], QUOTENAME(t.name), QUOTENAME(o.[name]), i.name 
FROM sys.indexes AS i (NOLOCK)
INNER JOIN sys.objects AS o (NOLOCK) ON o.[object_id] = i.[object_id]
INNER JOIN sys.tables AS mst (NOLOCK) ON mst.[object_id] = i.[object_id]
INNER JOIN sys.schemas AS t (NOLOCK) ON t.[schema_id] = mst.[schema_id]
WHERE i.[type] > 4'

		BEGIN TRY
			INSERT INTO #tblColStoreIXs
			EXECUTE sp_executesql @sqlcmd0
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Global trace flags subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		
		UPDATE #tmpdbs0
		SET isdone = 1
		WHERE dbid = @dbid0
	END
	
	SELECT @has_colstrix = COUNT(*) FROM #tblColStoreIXs
END;

IF (SELECT COUNT(TraceFlag) FROM @tracestatus WHERE [Global] = 1) >= 1
BEGIN
	SELECT 'Global_Trace_Flags' AS [Check], 
		CASE WHEN TraceFlag = 845 
				AND SERVERPROPERTY('EngineEdition') = 2 --Standard SKU
				AND ((@sqlmajorver = 10 AND ((@sqlminorver = 0 AND @sqlbuild >= 2714) OR @sqlminorver = 50)) 
					OR (@sqlmajorver = 9 AND @sqlbuild >= 4226))
				THEN '[INFORMATION: TF845 supports locking pages in memory in SQL Server Standard Editions]'
			WHEN TraceFlag = 845 
				AND SERVERPROPERTY('EngineEdition') = 2 --Standard SKU
				AND @sqlmajorver = 11
				THEN '[WARNING: TF845 is not needed in SQL 2012]'
			WHEN TraceFlag = 834
				AND @sqlmajorver >= 11
				AND @has_colstrix > 0
				THEN '[WARNING: TF834 (Large Page Support for BP) is discouraged when Column Store Indexes are used]' --http://support.microsoft.com/kb/920093
			WHEN TraceFlag = 1118 
				AND (@sqlmajorver >= 10 OR (@sqlmajorver = 9 AND @sqlbuild >= 3166))
				THEN '[INFORMATION: TF1118 forces uniform extent allocations instead of mixed page allocations]' --http://support.microsoft.com/kb/328551
			WHEN TraceFlag = 4135 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild >= 1787 AND @sqlbuild < 1818 
				THEN '[INFORMATION: TF4135 supports fixes and enhancements on the query optimizer]'
			WHEN TraceFlag = 4135 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild >= 1818 AND @sqlbuild < 2531 
				THEN '[WARNING: TF4199 should be used instead of TF4135 in this SQL build]'
			WHEN TraceFlag = 4135 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild >= 2531 AND @sqlbuild < 2766 
				THEN '[INFORMATION: TF4135 supports fixes and enhancements on the query optimizer]'
			WHEN TraceFlag = 4135 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild > = 2766 
				THEN '[INFORMATION: TF4135 supports fixes and enhancements on the query optimizer]'
			WHEN TraceFlag = 4135 
				AND @sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 1600 AND @sqlbuild < 1702 
				THEN '[INFORMATION: TF4135 supports fixes and enhancements on the query optimizer]'
			WHEN TraceFlag = 4135 
				AND @sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 1702 
				THEN '[WARNING: TF4199 should be used instead of TF4135 in this SQL build]'
			WHEN TraceFlag = 4199 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild >= 1787 AND @sqlbuild < 1818 
				THEN '[WARNING: TF4135 should be used instead of TF4199 in this SQL build]'
			WHEN TraceFlag = 4199 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild >= 1818 AND @sqlbuild < 2531 
				THEN '[INFORMATION: TF4199 supports fixes and enhancements on the query optimizer]'
			WHEN TraceFlag = 4199 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild >= 2531 AND @sqlbuild < 2766 
				THEN '[WARNING: TF4135 should be used instead of TF4199 in this SQL build]'
			WHEN TraceFlag = 4199 
				AND @sqlmajorver = 10 AND @sqlminorver = 0 AND @sqlbuild > = 2766 
				THEN '[WARNING: TF4135 should be used instead of TF4199 in this SQL build]'
			WHEN TraceFlag = 4199 
				AND @sqlmajorver >= 10 AND @sqlminorver = 50 AND @sqlbuild >= 1600 AND @sqlbuild < 1702 
				THEN '[WARNING: TF4135 should be used instead of TF4199 in this SQL build]'
			WHEN TraceFlag = 4199 
				AND @sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 1702 
				THEN '[INFORMATION: TF4199 supports fixes and enhancements on the query optimizer]'
			ELSE '[WARNING: Verify need to set a Non-default TF]'
		END AS [Deviation], TraceFlag		
	FROM @tracestatus 
	WHERE [Global]=1 
	ORDER BY TraceFlag;
END

IF (SELECT COUNT(TraceFlag) FROM @tracestatus WHERE [Global]=1) = 0
BEGIN
	SELECT 'Global_Trace_Flags' AS [Check], '[There are no Global Trace Flags active]' AS [Deviation]
END;
	
--------------------------------------------------------------------------------------------------------------------------------
-- System configurations subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting System configurations subsection', 10, 1) WITH NOWAIT
-- Focus on:
-- backup compression default
-- clr enabled (only enable if needed)
-- lightweight pooling (should be zero)
-- max degree of parallelism 
-- max server memory (MB) (set to an appropriate value)
-- priority boost (should be zero)
-- remote admin connections (should be enabled in a cluster configuration, to allow remote DAC)
-- scan for startup procs (should be disabled unless business requirement, like replication)
-- min memory per query (default is 1024KB)
-- allow updates (no effect in 2005 or above, but should be off)
-- max worker threads (should be zero in 2005 or above)

DECLARE @awe tinyint, @ssp bit, @bckcomp bit, @clr bit, @costparallel tinyint, @chain bit, @lpooling bit
DECLARE @adhoc smallint, @pboost bit, @qtimeout int, @cmdshell bit, @deftrace bit, @remote bit
DECLARE @minmemqry int, @allowupd bit, @mwthreads int, @recinterval int, @netsize smallint
DECLARE @ixmem smallint, @adhocqry bit, @locks int, @mwthreads_count int, @qrywait int

SELECT @mwthreads_count = max_workers_count FROM sys.dm_os_sys_info;

SELECT @awe = CONVERT(tinyint, [value]) FROM sys.configurations WHERE [Name] = 'awe enabled';
SELECT @bckcomp = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'backup compression default';
SELECT @clr = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'clr enabled';
SELECT @costparallel = CONVERT(tinyint, [value]) FROM sys.configurations WHERE [Name] = 'cost threshold for parallelism';
SELECT @chain = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'cross db ownership chaining';
SELECT @lpooling = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'lightweight pooling';
SELECT @pboost = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'priority boost';
SELECT @qtimeout = CONVERT(int, [value]) FROM sys.configurations WHERE [Name] = 'remote query timeout (s)';
SELECT @cmdshell = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'xp_cmdshell';
SELECT @deftrace = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'default trace enabled';
SELECT @remote = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'remote admin connections';
SELECT @ssp = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'scan for startup procs';
SELECT @minmemqry = CONVERT(int, [value]) FROM sys.configurations WHERE [Name] = 'min memory per query (KB)';
SELECT @allowupd = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'allow updates';
SELECT @mwthreads = CONVERT(smallint, [value]) FROM sys.configurations WHERE [Name] = 'max worker threads';
SELECT @recinterval = CONVERT(int, [value]) FROM sys.configurations WHERE [Name] = 'recovery interval (min)';
SELECT @netsize = CONVERT(smallint, [value]) FROM sys.configurations WHERE [Name] = 'network packet size (B)';
SELECT @ixmem = CONVERT(smallint, [value]) FROM sys.configurations WHERE [Name] = 'index create memory (KB)';
SELECT @locks = CONVERT(int, [value]) FROM sys.configurations WHERE [Name] = 'locks';
SELECT @qrywait = CONVERT(int, [value]) FROM sys.configurations WHERE [Name] = 'query wait (s)';
SELECT @adhocqry = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'ad hoc Distributed Queries';
SELECT @adhoc = CONVERT(bit, [value]) FROM sys.configurations WHERE [Name] = 'optimize for ad hoc workloads';

SELECT 'System_Configurations' AS [Check], 'Allow updates' AS [Setting], @allowupd AS [Current Value], CASE WHEN @allowupd = 0 THEN '[OK]' ELSE '[WARNING: Microsoft does not support direct catalog updates]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Ad Hoc Distributed Queries' AS [Setting], @adhocqry AS [Current Value], CASE WHEN @adhocqry = 0 THEN '[OK]' ELSE '[WARNING: Ad Hoc Distributed Queries are enabled]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'AWE' AS [Setting], @awe AS [Current Value], CASE WHEN @sqlmajorver < 11 AND @arch = 32 AND @systemmem >= 4000 AND @awe = 0 THEN '[WARNING: Current AWE setting is not optimal for this configuration]' WHEN @sqlmajorver < 11 AND @arch IS NULL THEN '[WARNING: Could not determine architecture needed for check]' WHEN @sqlmajorver > 10 THEN '[INFORMATION: AWE is not used from SQL Server 2012 onwards]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Backup Compression' AS [Setting], @bckcomp AS [Current Value], CASE WHEN @sqlmajorver > 9 AND @bckcomp = 0 THEN '[INFORMATION: Backup compression setting is not the recommended value]' WHEN @sqlmajorver < 10 THEN '[NA]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'CLR' AS [Setting], @clr AS [Current Value], CASE WHEN @clr = 1 THEN '[INFORMATION: CLR user code execution setting is enabled]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Cost threshold for Parallelism' AS [Setting], @costparallel AS [Current Value], CASE WHEN @costparallel = 5 THEN '[OK]' ELSE '[WARNING: Cost threshold for Parallelism setting is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Cross DB ownership Chaining' AS [Setting], @chain AS [Current Value], CASE WHEN @chain = 1 THEN '[WARNING: Cross DB ownership chaining setting is not the recommended value]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Default trace' AS [Setting], @deftrace AS [Current Value], CASE WHEN @deftrace = 0 THEN '[WARNING: Default trace setting is NOT enabled]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Index create memory (KB)' AS [Setting], @ixmem AS [Current Value], CASE WHEN @ixmem = 0 THEN '[OK]' WHEN @ixmem > 0 AND @ixmem < @minmemqry THEN '[WARNING: Index create memory should not be less than Min memory per query]' ELSE '[WARNING: Index create memory is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Lightweight pooling' AS [Setting], @lpooling AS [Current Value], CASE WHEN @lpooling = 1 THEN '[WARNING: Lightweight pooling setting is not the recommended value]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Locks' AS [Setting], @locks AS [Current Value], CASE WHEN @locks = 0 THEN '[OK]' ELSE '[WARNING: Locks option is not set with the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Max worker threads' AS [Setting], @mwthreads AS [Current Value], CASE WHEN @mwthreads = 0 THEN '[OK]' WHEN @mwthreads > 2048 AND @arch = 64 THEN '[WARNING: Max worker threads is larger than 2048 on a x64 system]' WHEN @mwthreads > 1024 AND @arch = 32 THEN '[WARNING: Max worker threads is larger than 1024 on a x86 system]' ELSE '[WARNING: Max worker threads is not the default value]' END AS [Deviation], CASE WHEN @mwthreads = 0 THEN '[INFORMATION: Configured workers = ' + CONVERT(VARCHAR(10),@mwthreads_count) + ']' ELSE '' END AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Min memory per query (KB)' AS [Setting], @minmemqry AS [Current Value], CASE WHEN @minmemqry = 1024 THEN '[OK]' ELSE '[WARNING: Min memory per query (KB) setting is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Network packet size (B)' AS [Setting], @netsize AS [Current Value], CASE WHEN @netsize = 4096 THEN '[OK]' ELSE '[WARNING: Network packet size is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Optimize for ad-hoc workloads' AS [Setting], @adhoc AS [Current Value], CASE WHEN @sqlmajorver > 9 AND @adhoc = 0 THEN '[INFORMATION: Consider enabling the Optimize for ad hoc workloads setting on heavy OLTP ad-hoc worloads to conserve resources]' WHEN @sqlmajorver < 10 THEN '[NA]' ELSE '[OK]' END AS [Deviation], CASE WHEN @sqlmajorver > 9 AND @adhoc = 0 THEN '[INFORMATION: Should be ON if SQL Server 2008 or higher and OLTP workload]' ELSE '' END AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Priority Boost' AS [Setting], @pboost AS [Current Value], CASE WHEN @pboost = 1 THEN '[CRITICAL: Priority boost setting is not the recommended value]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Query wait (s)' AS [Setting], @qrywait AS [Current Value], CASE WHEN @qrywait = -1 THEN '[OK]' ELSE '[CRITICAL: Query wait is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Recovery Interval (min)' AS [Setting], @recinterval AS [Current Value], CASE WHEN @recinterval = 0 THEN '[OK]' ELSE '[WARNING: Recovery interval is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Remote Admin Connections' AS [Setting], @remote AS [Current Value], CASE WHEN @remote = 0 AND @clustered = 1 THEN '[WARNING: Consider enabling the DAC listener to access a remote connections on a clustered configuration]' WHEN @remote = 0 AND @clustered = 0 THEN '[INFORMATION: Consider enabling remote connections access to the DAC listener on a stand-alone configuration, should local resources be exhausted]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Remote query timeout' AS [Setting], @qtimeout AS [Current Value], CASE WHEN @qtimeout = 600 THEN '[OK]' ELSE '[WARNING: Remote query timeout is not the default value]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'Startup Stored Procedures' AS [Setting], @ssp AS [Current Value], CASE WHEN @ssp = 1 AND (@replication IS NULL OR @replication = 0) THEN '[WARNING: Scanning for startup stored procedures setting is not the recommended value]' ELSE '[OK]' END AS [Deviation], '' AS [Comment]
UNION ALL
SELECT 'System_Configurations' AS [Check], 'xp_cmdshell' AS [Setting], @cmdshell AS [Current Value], CASE WHEN @cmdshell = 1 THEN '[WARNING: xp_cmdshell setting is enabled]' ELSE '[OK]' END AS [Deviation], '' AS [Comment];

IF (SELECT COUNT([Name]) FROM master.sys.configurations WHERE [value] <> [value_in_use] AND [is_dynamic] = 0) > 0
BEGIN
	SELECT 'System_Configurations_Pending'AS [Check], '[WARNING: There are system configurations with differences between running and configured values]' AS [Deviation]
	SELECT 'System_Configurations_Pending'AS [Information], [Name] AS [Setting],
		[value] AS 'Config_Value',
		[value_in_use] AS 'Run_Value'
	FROM master.sys.configurations (NOLOCK)
	WHERE [value] <> [value_in_use] AND [is_dynamic] = 0;
END
ELSE
BEGIN
	SELECT 'System_Configurations_Pending'AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- IFI subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting IFI subsection', 10, 1) WITH NOWAIT
IF @allow_xpcmdshell = 1
BEGIN
	DECLARE @ifi bit
	IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
		OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
			AND (SELECT COUNT(credential_id) FROM sys.credentials WHERE name = '##xp_cmdshell_proxy_account##') > 0)) -- Is not sysadmin but proxy account exists
		OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
			AND (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_cmdshell') > 0))
	BEGIN
		RAISERROR ('  |-Configuration options set for IFI check', 10, 1) WITH NOWAIT
		SELECT @sao = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'show advanced options'
		SELECT @xcmd = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'xp_cmdshell'
		IF @sao = 0
		BEGIN
			EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE;
		END
		IF @xcmd = 0
		BEGIN
			EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE;
		END

		BEGIN TRY
			DECLARE @xp_cmdshell_output TABLE ([Output] VARCHAR (8000));
			SET @CMD = ('whoami /priv')
			INSERT INTO @xp_cmdshell_output 
			EXEC master.dbo.xp_cmdshell @CMD;
			
			IF EXISTS (SELECT * FROM @xp_cmdshell_output WHERE [Output] LIKE '%SeManageVolumePrivilege%')
			BEGIN
				SELECT 'Instant_Initialization' AS [Check], '[OK]' AS [Deviation];
				SET @ifi = 1;
			END
			ELSE
			BEGIN
				SELECT 'Instant_Initialization' AS [Check], '[WARNING: Instant File Initialization is disabled. This can impact data file autogrowth times]' AS [Deviation];
				SET @ifi = 0
			END
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'IFI subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH

		IF @xcmd = 0
		BEGIN
			EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE WITH OVERRIDE;
		END
		IF @sao = 0
		BEGIN
			EXEC sp_configure 'show advanced options', 0; RECONFIGURE WITH OVERRIDE;
		END
	END
	ELSE
	BEGIN
		RAISERROR('[WARNING: Only a sysadmin can run the "Instant Initialization" check. A regular user can also run this check if a xp_cmdshell proxy account exists. Bypassing check]', 16, 1, N'xp_cmdshellproxy')
		RAISERROR('[WARNING: If not sysadmin, then must be a granted EXECUTE permissions on the following extended sprocs to run checks: xp_cmdshell. Bypassing check]', 16, 1, N'extended_sprocs')
		--RETURN
	END
END
ELSE
BEGIN
	RAISERROR(' |- [INFORMATION: "Instant Initialization" check was skipped because xp_cmdshell was not allowed.]', 10, 1, N'disallow_xp_cmdshell')
	--RETURN
END;

--------------------------------------------------------------------------------------------------------------------------------
-- LPIM subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting LPIM subsection', 10, 1) WITH NOWAIT
DECLARE @lpim bit, @lognumber int, @logcount int
IF @sqlmajorver > 9
BEGIN
	SET @sqlcmd = N'SELECT @lpimOUT = CASE WHEN locked_page_allocations_kb > 0 THEN 1 ELSE 0 END FROM sys.dm_os_process_memory (NOLOCK)'
	SET @params = N'@lpimOUT bit OUTPUT';
	EXECUTE sp_executesql @sqlcmd, @params, @lpimOUT=@lpim OUTPUT
END
ELSE IF @sqlmajorver = 9
BEGIN
	IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
		OR ISNULL(IS_SRVROLEMEMBER(N'securityadmin'), 0) = 1 -- Is securityadmin
		OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_readerrorlog') > 0
			AND (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_readerrorlog') > 0
			AND (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_enumerrorlogs') > 0)
	BEGIN
		IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#lpimdbcc%')
		DROP TABLE #lpimdbcc
		IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#lpimdbcc%')
		CREATE TABLE #lpimdbcc (logdate DATETIME, spid VARCHAR(50), logmsg VARCHAR(4000))

		IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#lpimavail_logs%')
		DROP TABLE #lpimavail_logs
		IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#lpimavail_logs%')
		CREATE TABLE #lpimavail_logs (lognum int, logdate DATETIME, logsize int) 

		-- Get the number of available logs 
		INSERT INTO #lpimavail_logs 
		EXEC xp_enumerrorlogs 
		
		SELECT MIN(lognum) FROM #lpimavail_logs WHERE DATEADD(dd, DATEDIFF(dd, 0, logdate), 0) >= DATEADD(dd, DATEDIFF(dd, 0, '06/17/2013  11:58'), 0)

		SELECT @logcount = ISNULL(MAX(lognum),@lognumber) FROM #lpimavail_logs WHERE DATEADD(dd, DATEDIFF(dd, 0, logdate), 0) >= DATEADD(dd, DATEDIFF(dd, 0, @StartDate), 0)

		IF @lognumber IS NULL
		BEGIN
			SELECT @ErrorMessage = '[WARNING: Could not retrieve information about Locked pages usage in SQL Server 2005]'
			RAISERROR (@ErrorMessage, 16, 1);
		END
		ELSE
		WHILE @lognumber < @logcount 
		BEGIN
			-- Cycle thru sql error logs (Cannot use Large Page Extensions:  lock memory privilege was not granted)
			SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''Using locked pages for buffer pool'''
			BEGIN TRY
				INSERT INTO #lpimdbcc (logdate, spid, logmsg) 
				EXECUTE (@sqlcmd);
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH
			-- Next log 
			--SET @lognumber = @lognumber + 1 
			SELECT @lognumber = MIN(lognum) FROM #lpimavail_logs WHERE lognum > @lognumber
		END 

		IF (SELECT COUNT(*) FROM #lpimdbcc) > 0
		BEGIN
			SET @lpim = 1
		END
		ELSE IF (SELECT COUNT(*) FROM #lpimdbcc) = 0 AND @lognumber IS NOT NULL
		BEGIN
			SET @lpim = 0
		END;
		
		DROP TABLE #lpimavail_logs;
		DROP TABLE #lpimdbcc;
	END
	ELSE
	BEGIN
		RAISERROR('[WARNING: Only a sysadmin or securityadmin can run the "Locked_pages" check. Bypassing check]', 16, 1, N'permissions')
		RAISERROR('[WARNING: If not sysadmin or securityadmin, then user must be a granted EXECUTE permissions on the following sprocs to run checks: xp_enumerrorlogs and sp_readerrorlog. Bypassing check]', 16, 1, N'extended_sprocs')
		--RETURN
	END;
END

IF @lpim = 0 AND @winver < 6.0 AND @arch = 64
BEGIN
	SELECT 'Locked_pages' AS [Check], '[WARNING: Locked pages are not in use by SQL Server. In a WS2003 x64 architecture it is recommended to enable LPIM]' AS [Deviation]
END
ELSE IF @lpim = 1 AND @winver < 6.0 AND @arch = 64
BEGIN
	SELECT 'Locked_pages' AS [Check], '[INFORMATION: Locked pages are being used by SQL Server. This is recommended in a WS2003 x64 architecture]' AS [Deviation]
END
ELSE IF @lpim = 1 AND @winver >= 6.0 AND @arch = 64
BEGIN
	SELECT 'Locked_pages' AS [Check], '[INFORMATION: Locked pages are being used by SQL Server. This is recommended in WS2008 or above only when there are signs of paging]' AS [Deviation]
END
ELSE IF @lpim IS NULL
BEGIN
	SELECT 'Locked_pages' AS [Check], '[Could_not_retrieve_information]' AS [Deviation]
END
ELSE
BEGIN
	SELECT 'Locked_pages' AS [Check], '[Not_used]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- DBs with collation <> master subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting DBs with collation <> master subsection', 10, 1) WITH NOWAIT
DECLARE @master_collate NVARCHAR(128), @dif_collate int
SELECT @master_collate = collation_name FROM master.sys.databases (NOLOCK) WHERE database_id = 1;
SELECT @dif_collate = COUNT(collation_name) FROM master.sys.databases (NOLOCK) WHERE collation_name <> @master_collate;

IF @dif_collate >= 1
BEGIN
	SELECT 'Collations' AS [Check], '[WARNING: Some user databases collation differ from the master Database_Collation]' AS [Deviation]
	SELECT 'Collations' AS [Information], name AS [Database_Name], collation_name AS [Database_Collation], @master_collate AS [Master_Collation]
	FROM master.sys.databases (NOLOCK)
	WHERE collation_name <> @master_collate;
END
ELSE
BEGIN
	SELECT 'Collations' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- DBs with skewed compatibility level subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting DBs with skewed compatibility level subsection', 10, 1) WITH NOWAIT
DECLARE @dif_compat int
SELECT @dif_compat = COUNT([compatibility_level]) FROM master.sys.databases (NOLOCK) WHERE [compatibility_level] <> @sqlmajorver * 10;

IF @dif_compat >= 1
BEGIN
	SELECT 'Compatibility_Level' AS [Check], '[WARNING: Some user databases have a non-optimal compatibility level]' AS [Deviation]
	SELECT 'Compatibility_Level' AS [Information], name AS [Database_Name], [compatibility_level] AS [Compatibility_Level]
	FROM master.sys.databases (NOLOCK)
	WHERE [compatibility_level] <> @sqlmajorver * 10;
END
ELSE
BEGIN
	SELECT 'Compatibility_Level' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- User DBs with non-default options subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting User DBs with non-default options subsection', 10, 1) WITH NOWAIT
DECLARE @cnt int, @cnt_i int
DECLARE @is_auto_close_on bit, @is_auto_shrink_on bit, @page_verify_option bit
DECLARE @is_auto_create_stats_on bit, @is_auto_update_stats_on bit
DECLARE @is_db_chaining_on bit, @is_indirect_checkpoint_on bit
DECLARE @is_trustworthy_on bit, @is_parameterization_forced bit

DECLARE @dbopterrtb TABLE (id int, 
	name sysname, 
	is_auto_close_on bit, 
	is_auto_shrink_on bit, 
	page_verify_option tinyint, 
	page_verify_option_desc NVARCHAR(60),
	is_auto_create_stats_on bit, 
	is_auto_update_stats_on bit,
	is_db_chaining_on bit,
	is_indirect_checkpoint_on bit,
	is_trustworthy_on bit,
	is_parameterization_forced bit)

IF @sqlmajorver < 11
BEGIN
	SET @sqlcmd = 'SELECT ROW_NUMBER() OVER(ORDER BY name), name, is_auto_close_on, 
	is_auto_shrink_on, page_verify_option, page_verify_option_desc,	
	is_auto_create_stats_on, is_auto_update_stats_on, 
	is_db_chaining_on, 0 AS is_indirect_checkpoint_on, is_trustworthy_on, is_parameterization_forced
FROM master.sys.databases (NOLOCK)
WHERE database_id > 4 OR name = ''model'''
END
ELSE
BEGIN
	SET @sqlcmd = 'SELECT ROW_NUMBER() OVER(ORDER BY name), name, is_auto_close_on, 
	is_auto_shrink_on, page_verify_option, page_verify_option_desc,	
	is_auto_create_stats_on, is_auto_update_stats_on, 
	is_db_chaining_on, CASE WHEN target_recovery_time_in_seconds > 0 THEN 1 ELSE 0 END AS is_indirect_checkpoint_on, 
	is_trustworthy_on, is_parameterization_forced
FROM master.sys.databases (NOLOCK)
WHERE database_id > 4 OR name = ''model'''
END	

INSERT INTO @dbopterrtb
EXECUTE sp_executesql @sqlcmd;

SET @cnt = (SELECT COUNT(id) FROM @dbopterrtb)
SET @cnt_i = 1

SELECT @is_auto_close_on = 0, @is_auto_shrink_on = 0, @page_verify_option = 0, @is_auto_create_stats_on = 0, @is_auto_update_stats_on = 0, @is_db_chaining_on = 0, @is_indirect_checkpoint_on = 0, @is_trustworthy_on = 0, @is_parameterization_forced = 0

WHILE @cnt_i <> @cnt
BEGIN 
	SELECT @is_auto_close_on = CASE WHEN is_auto_close_on = 1 AND @is_auto_close_on = 0 THEN 1 ELSE @is_auto_close_on END,
		@is_auto_shrink_on = CASE WHEN is_auto_shrink_on = 1 AND @is_auto_shrink_on = 0 THEN 1 ELSE @is_auto_shrink_on END, 
		@page_verify_option = CASE WHEN page_verify_option <> 2 AND @page_verify_option = 0 THEN 1 ELSE @page_verify_option END, 
		@is_auto_create_stats_on = CASE WHEN is_auto_create_stats_on = 0 AND @is_auto_create_stats_on = 0 THEN 1 ELSE @is_auto_create_stats_on END, 
		@is_auto_update_stats_on = CASE WHEN is_auto_update_stats_on = 0 AND @is_auto_update_stats_on = 0 THEN 1 ELSE @is_auto_update_stats_on END, 
		@is_db_chaining_on = CASE WHEN is_db_chaining_on = 1 AND @is_db_chaining_on = 0 THEN 1 ELSE @is_db_chaining_on END,
		@is_indirect_checkpoint_on = CASE WHEN is_indirect_checkpoint_on = 1 AND @is_indirect_checkpoint_on = 0 THEN 1 ELSE @is_indirect_checkpoint_on END,
		@is_trustworthy_on = CASE WHEN is_trustworthy_on = 1 AND @is_trustworthy_on = 0 THEN 1 ELSE @is_trustworthy_on END,
		@is_parameterization_forced = CASE WHEN is_parameterization_forced = 1 AND @is_parameterization_forced = 0 THEN 1 ELSE @is_parameterization_forced END
	FROM @dbopterrtb
	WHERE id = @cnt_i;
	SET @cnt_i = @cnt_i + 1
END

IF @is_auto_close_on = 1 OR @is_auto_shrink_on = 1 OR @page_verify_option = 1 OR @is_auto_create_stats_on = 1 OR @is_auto_update_stats_on = 1 OR @is_db_chaining_on = 1 OR @is_indirect_checkpoint_on = 1
BEGIN
	SELECT 'Database_Options' AS [Check], '[WARNING: Some user databases may have Non-optimal_Settings]' AS [Deviation]
	SELECT 'Database_Options' AS [Information],
		name AS [Database_Name],
		RTRIM(
			CASE WHEN is_auto_close_on = 1 THEN 'Auto_Close;' ELSE '' END + 
			CASE WHEN is_auto_shrink_on = 1 THEN 'Auto_Shrink;' ELSE '' END +
			CASE WHEN page_verify_option <> 2 THEN 'Page_Verify;' ELSE '' END +
			CASE WHEN is_auto_create_stats_on = 0 THEN 'Auto_Create_Stats;' ELSE '' END +
			CASE WHEN is_auto_update_stats_on = 0 THEN 'Auto_Update_Stats;' ELSE '' END +
			CASE WHEN is_db_chaining_on = 1 THEN 'DB_Chaining;' ELSE '' END +
			CASE WHEN is_indirect_checkpoint_on = 1 THEN 'Indirect_Checkpoint;' ELSE '' END +
			CASE WHEN is_trustworthy_on = 1 THEN 'Trustworthy_bit;' ELSE '' END +
			CASE WHEN is_parameterization_forced = 1 THEN 'Forced_Parameterization;' ELSE '' END
		) AS [Non-optimal_Settings],
		CASE WHEN is_auto_close_on = 1 THEN 'ON' ELSE 'OFF' END AS [Auto_Close],
		CASE WHEN is_auto_shrink_on = 1 THEN 'ON' ELSE 'OFF' END AS [Auto_Shrink], 
		page_verify_option_desc AS [Page_Verify], 
		CASE WHEN is_auto_create_stats_on = 1 THEN 'ON' ELSE 'OFF' END AS [Auto_Create_Stats],
		CASE WHEN is_auto_update_stats_on = 1 THEN 'ON' ELSE 'OFF' END AS [Auto_Update_Stats], 
		CASE WHEN is_db_chaining_on = 1 THEN 'ON' ELSE 'OFF' END AS [DB_Chaining],
		CASE WHEN is_indirect_checkpoint_on = 1 THEN 'ON' ELSE 'OFF' END AS [Indirect_Checkpoint], -- Meant just as a warning that Indirect_Checkpoint is ON. Should be OFF in OLTP systems.
		CASE WHEN is_trustworthy_on = 1 THEN 'ON' ELSE 'OFF' END AS [Trustworthy_bit],
		CASE WHEN is_parameterization_forced = 1 THEN 'ON' ELSE 'OFF' END AS [Forced_Parameterization]
	FROM @dbopterrtb
	WHERE is_auto_close_on = 1 OR is_auto_shrink_on = 1 OR page_verify_option <> 2 OR is_db_chaining_on = 1 OR is_auto_create_stats_on = 0 
		OR is_auto_update_stats_on = 0 OR is_indirect_checkpoint_on = 1 OR is_trustworthy_on = 1 OR is_parameterization_forced = 1;
END
ELSE
BEGIN
	SELECT 'Database_Options' AS [Check], '[OK]' AS [Deviation]
END;

IF (SELECT COUNT(*) FROM master.sys.databases (NOLOCK) WHERE is_auto_update_stats_on = 0 AND is_auto_update_stats_async_on = 1) > 0
BEGIN
	SELECT 'Database_Options_Disabled_Async_AutoUpdate' AS [Check], '[WARNING: Some databases have Auto_Update_Statistics_Asynchronously ENABLED while Auto_Update_Statistics is DISABLED. If asynch auto statistics update is intended, also enable Auto_Update_Statistics]' AS [Deviation]
	SELECT 'Database_Options_Disabled_Async_AutoUpdate' AS [Check], [name] FROM master.sys.databases (NOLOCK) WHERE is_auto_update_stats_on = 0 AND is_auto_update_stats_async_on = 1
END
ELSE
BEGIN
	SELECT 'Database_Options_Disabled_Async_AutoUpdate' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- DBs Autogrow in percentage subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting DBs Autogrow in percentage subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(is_percent_growth) FROM sys.master_files WHERE is_percent_growth = 1) > 0
BEGIN
	SELECT 'Percent_Autogrows' AS [Check], '[WARNING: Some database files have a growth ratio set in percentage. Over time, this could lead to uncontrolled disk space allocation and extended time to perform these growths]' AS [Deviation]
	SELECT 'Percent_Autogrows' AS [Information], database_id,
		DB_NAME(database_id) AS [Database_Name], 
		mf.name AS [Logical_Name],
		mf.size*8 AS [Current_Size_KB],
		mf.type_desc AS [File_Type],
		CASE WHEN is_percent_growth = 1 THEN 'pct' ELSE 'pages' END AS [Growth_Type],
		CASE WHEN is_percent_growth = 1 THEN mf.growth ELSE mf.growth*8 END AS [Growth_Amount],
		CASE WHEN is_percent_growth = 1 AND mf.growth > 0 THEN ((mf.size*8)*CONVERT(bigint, mf.growth))/100 
			WHEN is_percent_growth = 0 AND mf.growth > 0 THEN mf.growth*8 
			ELSE 0 END AS [Next_Growth_KB],
		CASE WHEN @ifi = 0 AND mf.type = 0 THEN 'Instant File Initialization is disabled'
			WHEN @ifi = 1 AND mf.type = 0 THEN 'Instant File Initialization is enabled'
			ELSE '' END AS [Comments]
	FROM sys.master_files mf (NOLOCK)
	WHERE is_percent_growth = 1
	GROUP BY database_id, mf.name, mf.size, is_percent_growth, mf.growth, mf.type_desc, mf.type
	ORDER BY 3, 4
END
ELSE
BEGIN
	SELECT 'Percent_Autogrows' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- DBs Autogrowth > 1GB in Logs or Data (when IFI is disabled) subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting DBs Autogrowth > 1GB in Logs or Data (when IFI is disabled) subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(growth) FROM sys.master_files 
	WHERE type >= CASE WHEN @ifi = 1 THEN 0 ELSE 1 END 
		AND type < 2 
		AND ((is_percent_growth = 1 AND ((size*8)*growth)/100 > 1048576) 
		OR (is_percent_growth = 0 AND growth*8 > 1048576))) > 0
BEGIN
	SELECT 'Large_Autogrows' AS [Check], '[WARNING: Some database files have set growth over 1GB. This could lead to extended growth times, slowing down your system]' AS [Deviation]
	SELECT 'Large_Autogrows' AS [Information], database_id,
		DB_NAME(database_id) AS [Database_Name], 
		mf.name AS [Logical_Name],
		mf.size*8 AS [Current_Size_KB],
		mf.type_desc AS [File_Type],
		CASE WHEN is_percent_growth = 1 THEN 'pct' ELSE 'pages' END AS [Growth_Type],
		CASE WHEN is_percent_growth = 1 THEN mf.growth ELSE mf.growth*8 END AS [Growth_Amount],
		CASE WHEN is_percent_growth = 1 AND mf.growth > 0 THEN ((CONVERT(bigint,mf.size)*8)*mf.growth)/100 
			WHEN is_percent_growth = 0 AND mf.growth > 0 THEN mf.growth*8 
			ELSE 0 END AS [Next_Growth_KB],
		CASE WHEN @ifi = 0 AND mf.type = 0 THEN 'Instant File Initialization is disabled'
			WHEN @ifi = 1 AND mf.type = 0 THEN 'Instant File Initialization is enabled'
			ELSE '' END AS [Comments]
	FROM sys.master_files mf (NOLOCK)
	WHERE mf.type >= CASE WHEN @ifi = 1 THEN 0 ELSE 1 END 
		AND mf.type < 2 
		AND (CASE WHEN is_percent_growth = 1 AND mf.growth > 0 THEN ((CONVERT(bigint,mf.size)*8)*mf.growth)/100 
			WHEN is_percent_growth = 0 AND mf.growth > 0 THEN mf.growth*8 
			ELSE 0 END) > 1048576
	GROUP BY database_id, mf.name, mf.size, is_percent_growth, mf.growth, mf.type_desc, mf.type
	ORDER BY 3, 4
END
ELSE
BEGIN
	SELECT 'Large_Autogrows' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Data files and Logs / tempDB and user Databases in same volume (Mountpoint aware) subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Data files and Logs / tempDB and user Databases in same volume (Mountpoint aware) subsection', 10, 1) WITH NOWAIT
IF @allow_xpcmdshell = 1
BEGIN
	DECLARE /*@dbid int,*/ @ctr2 int, @pserr bit
	SET @pserr = 0
	IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
	OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
		AND (SELECT COUNT(credential_id) FROM sys.credentials WHERE name = '##xp_cmdshell_proxy_account##') > 0) -- Is not sysadmin but proxy account exists
		AND (SELECT COUNT(l.name)
		FROM sys.server_permissions p (NOLOCK) INNER JOIN sys.server_principals l (NOLOCK)
		ON p.grantee_principal_id = l.principal_id
			AND p.class = 100 -- Server
			AND p.state IN ('G', 'W') -- Granted or Granted with Grant
			AND l.is_disabled = 0
			AND p.permission_name = 'ALTER SETTINGS'
			AND QUOTENAME(l.name) = QUOTENAME(USER_NAME())) = 0) -- Is not sysadmin but has alter settings permission 
	OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
		AND ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_fileexist') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_instance_regread') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OAGetErrorInfo') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OACreate') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OADestroy') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_cmdshell') > 0 AND
		(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regenumvalues') > 0)))
	BEGIN
		IF @sqlmajorver < 11 OR (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild <= 2500)
		BEGIN
			DECLARE @pstbl TABLE ([KeyExist] int)
			BEGIN TRY
				INSERT INTO @pstbl
				EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\PowerShell\1' -- check if Powershell is installed
			END TRY
			BEGIN CATCH
				SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
				SELECT @ErrorMessage = 'Data files and Logs in same volume (Mountpoint aware) subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
				RAISERROR (@ErrorMessage, 16, 1);
			END CATCH

			SELECT @sao = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'show advanced options'
			SELECT @xcmd = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'xp_cmdshell'
			SELECT @ole = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'Ole Automation Procedures'

			RAISERROR ('  |-Configuration options set for Data and Log location check', 10, 1) WITH NOWAIT
			IF @sao = 0
			BEGIN
				EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE;
			END
			IF @xcmd = 0
			BEGIN
				EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE;
			END
			IF @ole = 0
			BEGIN
				EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE WITH OVERRIDE;
			END
		
			IF (SELECT [KeyExist] FROM @pstbl) = 1
			BEGIN
				DECLARE @ctr int
				DECLARE @output_hw_tot TABLE ([PS_OUTPUT] NVARCHAR(2048));
				DECLARE @output_hw_format TABLE ([volid] smallint IDENTITY(1,1), [HD_Volume] NVARCHAR(2048) NULL)
				
				IF @custompath IS NULL
				BEGIN
					--IF @sqlmajorver < 11
					--BEGIN
						EXEC master..xp_instance_regread N'HKEY_LOCAL_MACHINE',N'Software\Microsoft\MSSQLServer\Setup',N'SQLPath', @path OUTPUT
						SET @path = @path + '\LOG'
					--END
					--ELSE
					--BEGIN
					--	SET @sqlcmd = N'SELECT @pathOUT = LEFT([path], LEN([path])-1) FROM sys.dm_os_server_diagnostics_log_configurations';
					--	SET @params = N'@pathOUT NVARCHAR(2048) OUTPUT';
					--	EXECUTE sp_executesql @sqlcmd, @params, @pathOUT=@path OUTPUT;
					--END
					
					-- Create COM object with FSO
					EXEC @OLEResult = master.dbo.sp_OACreate 'Scripting.FileSystemObject', @FSO OUT
					IF @OLEResult <> 0
					BEGIN
						EXEC sp_OAGetErrorInfo @FSO, @src OUT, @desc OUT
						SELECT @ErrorMessage = 'Error Creating COM Component 0x%x, %s, %s'
						RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
					END
					ELSE
					BEGIN
						EXEC @OLEResult = master.dbo.sp_OAMethod @FSO, 'FolderExists', @existout OUT, @path
						IF @OLEResult <> 0
						BEGIN
							EXEC sp_OAGetErrorInfo @FSO, @src OUT, @desc OUT
							SELECT @ErrorMessage = 'Error Calling FolderExists Method 0x%x, %s, %s'
							RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
						END
						ELSE
						BEGIN
							IF @existout <> 1
							BEGIN
								SET @path = CONVERT(NVARCHAR(500), SERVERPROPERTY('ErrorLogFileName'))
								SET @path = LEFT(@path,LEN(@path)-CHARINDEX('\', REVERSE(@path)))
							END 
						END
						EXEC @OLEResult = sp_OADestroy @FSO
					END
				END
				ELSE
				BEGIN
					SELECT @path = CASE WHEN @custompath LIKE '%\' THEN LEFT(@custompath, LEN(@custompath)-1) ELSE @custompath END
				END
				
				SET @FileName = @path + '\checkbp_' + RTRIM(@server) + '.ps1'
				
				EXEC master.dbo.xp_fileexist @FileName, @existout out
				IF @existout = 0
				BEGIN 
					-- Scan for local disks
					SET @Text1 = '[string] $serverName = ''localhost''
$vols = Get-WmiObject -computername $serverName -query "select Name from Win32_Volume where Capacity <> NULL and DriveType = 3"
foreach($vol in $vols)
{
	[string] $drive = "{0}" -f $vol.name
	Write-Output $drive
}'
					-- Create COM object with FSO
					EXEC @OLEResult = master.dbo.sp_OACreate 'Scripting.FileSystemObject', @FS OUT
					IF @OLEResult <> 0
					BEGIN
						EXEC sp_OAGetErrorInfo @FS, @src OUT, @desc OUT
						SELECT @ErrorMessage = 'Error Creating COM Component 0x%x, %s, %s'
						RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
					END

					--Open file
					EXEC @OLEResult = master.dbo.sp_OAMethod @FS, 'OpenTextFile', @FileID OUT, @FileName, 2, 1
					IF @OLEResult <> 0
					BEGIN
						EXEC sp_OAGetErrorInfo @FS, @src OUT, @desc OUT
						SELECT @ErrorMessage = 'Error Calling OpenTextFile Method 0x%x, %s, %s' + CHAR(10) + 'Could not create file ' + @FileName
						RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
					END
					ELSE
					BEGIN
						SELECT @ErrorMessage = '  |-Created file ' + @FileName
						RAISERROR (@ErrorMessage, 10, 1) WITH NOWAIT
					END

					--Write Text1
					EXEC @OLEResult = master.dbo.sp_OAMethod @FileID, 'WriteLine', NULL, @Text1
					IF @OLEResult <> 0
					BEGIN
						EXEC sp_OAGetErrorInfo @FS, @src OUT, @desc OUT
						SELECT @ErrorMessage = 'Error Calling WriteLine Method 0x%x, %s, %s' + CHAR(10) + 'Could not write to file ' + @FileName
						RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
					END

					EXEC @OLEResult = sp_OADestroy @FileID
					EXEC @OLEResult = sp_OADestroy @FS
				END	
				ELSE
				BEGIN
					SELECT @ErrorMessage = '  |-Reusing file ' + @FileName
					RAISERROR (@ErrorMessage, 10, 1) WITH NOWAIT
				END
					
				SET @CMD = 'powershell -NoLogo -NoProfile -File "' + @FileName + '"'
				INSERT INTO @output_hw_tot 
				EXEC master.dbo.xp_cmdshell @CMD

				SET @CMD = 'del /Q "' + @FileName + '"'
				EXEC master.dbo.xp_cmdshell @CMD, NO_OUTPUT

				IF (SELECT COUNT([PS_OUTPUT]) 
				FROM @output_hw_tot WHERE [PS_OUTPUT] LIKE '%cannot be loaded because%'
					OR [PS_OUTPUT] LIKE '%scripts is disabled%') = 0
				BEGIN
					INSERT INTO @output_hw_format ([HD_Volume])
					SELECT RTRIM([PS_OUTPUT]) 
					FROM @output_hw_tot 
					WHERE [PS_OUTPUT] IS NOT NULL
				END
				ELSE
				BEGIN
					SET @pserr = 1
					RAISERROR ('[WARNING: Powershell script cannot be loaded because the execution of scripts is disabled on this system.
To change the execution policy, type the following command in Powershell console: Set-ExecutionPolicy RemoteSigned
The Set-ExecutionPolicy cmdlet enables you to determine which Windows PowerShell scripts (if any) will be allowed to run on your computer. 
Windows PowerShell has four different execution policies:
	Restricted - No scripts can be run. Windows PowerShell can be used only in interactive mode.
	AllSigned - Only scripts signed by a trusted publisher can be run.
	RemoteSigned - Downloaded scripts must be signed by a trusted publisher before they can be run.
		|- REQUIRED by BP Check
	Unrestricted - No restrictions; all Windows PowerShell scripts can be run.]
',16,1);	
				END
		
				SET @CMD2 = 'del ' + @FileName
				EXEC master.dbo.xp_cmdshell @CMD2, NO_OUTPUT;
			END
			ELSE
			BEGIN
				SET @pserr = 1
				RAISERROR ('[WARNING: Powershell is not present. Bypassing Data files and Logs in same volume check]',16,1);	
			END
			
			IF @xcmd = 0
			BEGIN
				EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE WITH OVERRIDE;
			END
			IF @ole = 0
			BEGIN
				EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE WITH OVERRIDE;
			END
			IF @sao = 0
			BEGIN
				EXEC sp_configure 'show advanced options', 0; RECONFIGURE WITH OVERRIDE;
			END
		END
		ELSE
		BEGIN
			INSERT INTO @output_hw_format ([HD_Volume])
			EXEC ('SELECT DISTINCT(volume_mount_point) FROM sys.master_files mf CROSS APPLY sys.dm_os_volume_stats (database_id, [file_id]) WHERE mf.[file_id] < 65537')
		END;

		IF @pserr = 0
		BEGIN
			-- select mountpoints only
			DECLARE @intertbl TABLE (physical_name nvarchar(260))
			INSERT INTO @intertbl
			SELECT physical_name
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2
				ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE ([database_id] > 4 OR [database_id] = 2)
				AND [database_id] <> 32767 AND LEN(t2.HD_Volume) > 3

			-- select database files in mountpoints		
			DECLARE @filetbl TABLE (database_id int, type tinyint, file_id int, physical_name nvarchar(260), volid smallint)
			INSERT INTO @filetbl
			SELECT database_id, type, file_id, physical_name, volid
				FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2 ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
				WHERE ([database_id] > 4 OR [database_id] = 2) AND [database_id] <> 32767 AND LEN(t2.HD_Volume) > 3
				UNION ALL
				-- select database files not in mountpoints
				SELECT database_id, type, file_id, physical_name, volid
				FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2 ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
				WHERE ([database_id] > 4 OR [database_id] = 2) AND [database_id] <> 32767 AND physical_name NOT IN (SELECT physical_name FROM @intertbl)
				
			SELECT @ctr = COUNT(DISTINCT(t1.[database_id])) FROM @filetbl t1 
			INNER JOIN @filetbl t2 ON t1.database_id = t2.database_id
				AND t1.[type] <> t2.[type]
				AND ((t1.[type] = 1 AND t2.[type] <> 1) OR (t2.[type] = 1 AND t1.[type] <> 1))
				AND t1.volid = t2.volid;

			IF @ctr > 0
			BEGIN
				SELECT 'Data_and_Log_locations' AS [Check], '[WARNING: Some user databases have Data and Log files in the same physical volume]' AS [Deviation]
				SELECT DISTINCT 'Data_and_Log_locations' AS [Information], DB_NAME(mf.[database_id]) AS [Database_Name], type_desc AS [Type], mf.physical_name
				FROM sys.master_files mf (NOLOCK) INNER JOIN @filetbl t1 ON mf.database_id = t1.database_id AND mf.physical_name = t1.physical_name
					INNER JOIN @filetbl t2 ON t1.database_id = t2.database_id
						AND t1.[type] <> t2.[type]
						AND ((t1.[type] = 1 AND t2.[type] <> 1) OR (t2.[type] = 1 AND t1.[type] <> 1))
						AND t1.volid = t2.volid
				ORDER BY mf.physical_name OPTION (RECOMPILE);
			END
			ELSE
			BEGIN
				SELECT 'Data_and_Log_locations' AS [Check], '[OK]' AS [Deviation]
			END;

			-- select tempDB mountpoints only
			DECLARE @intertbl2 TABLE (physical_name nvarchar(260))
			INSERT INTO @intertbl2
			SELECT physical_name
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2
			ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] = 2 AND LEN(t2.HD_Volume) > 3 AND [type] = 0
			
			-- select user DBs mountpoints only
			DECLARE @intertbl3 TABLE (physical_name nvarchar(260))
			INSERT INTO @intertbl3
			SELECT physical_name
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2
			ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] > 4 AND [database_id] <> 32767 AND LEN(t2.HD_Volume) > 3 AND [type] = 0
			
			-- select tempDB files in mountpoints		
			DECLARE @tempDBtbl TABLE (database_id int, type tinyint, file_id int, physical_name nvarchar(260), volid smallint)
			INSERT INTO @tempDBtbl
			SELECT database_id, type, file_id, physical_name, volid
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2 ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] = 2 AND LEN(t2.HD_Volume) > 3 AND [type] = 0
			UNION ALL
			SELECT database_id, type, file_id, physical_name, volid
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2 ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] = 2 AND [type] = 0 AND physical_name NOT IN (SELECT physical_name FROM @intertbl2)

			-- select user DBs files in mountpoints		
			DECLARE @otherstbl TABLE (database_id int, type tinyint, file_id int, physical_name nvarchar(260), volid smallint)
			INSERT INTO @otherstbl
			SELECT database_id, type, file_id, physical_name, volid
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2 ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] > 4 AND [database_id] <> 32767 AND LEN(t2.HD_Volume) > 3 AND [type] = 0
			UNION ALL
			SELECT database_id, type, file_id, physical_name, volid
			FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format t2 ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] > 4 AND [database_id] <> 32767 AND [type] = 0 AND physical_name NOT IN (SELECT physical_name FROM @intertbl3)

			SELECT @ctr = COUNT(DISTINCT(t1.[database_id])) FROM @otherstbl t1 INNER JOIN @tempDBtbl t2 ON t1.volid = t2.volid;

			SELECT @ctr2 = COUNT(*) FROM @tempDBtbl WHERE LEFT(physical_name, 1) = 'C'

			IF @ctr > 0
			BEGIN
				SELECT 'tempDB_location' AS [Check], '[WARNING: tempDB is on the same physical volume as user databases]' AS [Deviation];
			END
			ELSE IF @ctr2 > 0
			BEGIN
				SELECT 'tempDB_location' AS [Check], '[WARNING: tempDB is on C: drive]' AS [Deviation]
			END
			ELSE
			BEGIN
				SELECT 'tempDB_location' AS [Check], '[OK]' AS [Deviation]
			END;
			
			IF @ctr > 0 OR @ctr2 > 0
			BEGIN
				SELECT DISTINCT 'tempDB_location' AS [Information], DB_NAME(mf.[database_id]) AS [Database_Name], type_desc AS [Type], mf.physical_name
				FROM sys.master_files mf (NOLOCK) INNER JOIN @otherstbl t1 ON mf.database_id = t1.database_id AND mf.physical_name = t1.physical_name
					INNER JOIN @tempDBtbl t2 ON t1.volid = t2.volid
				UNION ALL
				SELECT DISTINCT 'tempDB_location' AS [Information], DB_NAME(mf.[database_id]) AS [Database_Name], type_desc AS [Type], mf.physical_name
				FROM sys.master_files mf (NOLOCK) INNER JOIN @tempDBtbl t1 ON mf.database_id = t1.database_id AND mf.physical_name = t1.physical_name
				ORDER BY DB_NAME(mf.[database_id]) OPTION (RECOMPILE);
			END
		END
		ELSE
		BEGIN
			SELECT 'Data_and_Log_locations' AS [Check], '[WARNING: Could not gather information on file locations]' AS [Deviation]
			SELECT 'tempDB_location' AS [Check], '[WARNING: Could not gather information on file locations]' AS [Deviation]
		END
	END
	ELSE
	BEGIN
		RAISERROR('[WARNING: Only a sysadmin can run the "Data files and Logs / tempDB and user Databases in same volume" checks. A regular user can also run this check if a xp_cmdshell proxy account exists. Bypassing check]', 16, 1, N'xp_cmdshellproxy')
		RAISERROR('[WARNING: If not sysadmin, then must be a granted EXECUTE permissions on the following extended sprocs to run checks: sp_OACreate, sp_OADestroy, sp_OAGetErrorInfo, xp_cmdshell, xp_instance_regread, xp_regread, xp_fileexist and xp_regenumvalues. Bypassing check]', 16, 1, N'extended_sprocs')
		--RETURN
	END
END
ELSE
BEGIN
	RAISERROR(' |- [INFORMATION: "Data files and Logs / tempDB and user Databases in same volume" check was skipped because xp_cmdshell was not allowed.]', 10, 1, N'disallow_xp_cmdshell')
	--RETURN
END;

--------------------------------------------------------------------------------------------------------------------------------
-- All tempDB Files are of equal size and even number subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting All tempDB files are of equal size and even number subsection', 10, 1) WITH NOWAIT
DECLARE @tdb_files int
SELECT @tdb_files = COUNT(physical_name) FROM sys.master_files (NOLOCK) WHERE database_id = 2 AND type = 0;

IF @tdb_files >= 4
BEGIN
	SELECT 'tempDB_files' AS [Check], 
		CASE WHEN (SELECT COUNT(DISTINCT size)
				FROM sys.master_files
				WHERE database_id = 2 AND type = 0) > 1 
					AND @tdb_files % 2 > 0 THEN '[WARNING: Data file sizes do not match and Number of data files are not even]'
			WHEN (SELECT COUNT(DISTINCT size)
				FROM sys.master_files
				WHERE database_id = 2 AND type = 0) > 1 THEN '[WARNING: Data file sizes do not match]'
			WHEN @tdb_files % 2 > 0 THEN '[WARNING: Number of data files are not even]'
	ELSE '[OK]' END AS [Deviation];
	SELECT 'tempDB_files' AS [Information], physical_name AS [tempDB_Files], CAST((size*8)/1024.0 AS DECIMAL(18,2)) AS [File_Size_MB]
	FROM sys.master_files (NOLOCK)
	WHERE database_id = 2 AND type = 0;
END
ELSE
BEGIN
	SELECT 'tempDB_files' AS [Check], '[INFORMATION: tempDB has only ' + CONVERT(VARCHAR(10), @tdb_files) + ' file(s). Consider creating at least a total of 4 tempDB data files' + CASE WHEN @tdb_files % 2 > 0 AND @tdb_files > 1 THEN ' . Also, number of data files are not even]' ELSE ']' END AS [Deviation]
	SELECT 'tempDB_files' AS [Information], physical_name AS [tempDB_Files], CAST((size*8)/1024.0 AS DECIMAL(18,2)) AS [File_Size_MB]
	FROM sys.master_files (NOLOCK)
	WHERE database_id = 2 AND type = 0;
END;

--------------------------------------------------------------------------------------------------------------------------------
-- tempDB Files autogrow of equal size subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting tempDB Files autogrow of equal size subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(DISTINCT growth) FROM sys.master_files WHERE [database_id] = 2 AND [type] = 0) > 1
	OR (SELECT COUNT(DISTINCT is_percent_growth) FROM sys.master_files WHERE [database_id] = 2 AND [type] = 0) > 1
BEGIN
	SELECT 'tempDB_files_Autogrow' AS [Check], '[WARNING: Some tempDB data files have different growth settings]' AS [Deviation]
	SELECT 'tempDB_files_Autogrow' AS [Information], 
		DB_NAME(2) AS [Database_Name], 
		mf.name AS [Logical_Name],
		mf.[size]*8 AS [Current_Size_KB],
		mf.type_desc AS [File_Type],
		CASE WHEN is_percent_growth = 1 THEN 'pct' ELSE 'pages' END AS [Growth_Type],
		CASE WHEN is_percent_growth = 1 THEN mf.growth ELSE mf.growth*8 END AS [Growth_Amount],
		CASE WHEN is_percent_growth = 1 AND mf.growth > 0 THEN ((mf.size*8)*CONVERT(bigint, mf.growth))/100 
			WHEN is_percent_growth = 0 AND mf.growth > 0 THEN mf.growth*8 
			ELSE 0 END AS [Next_Growth_KB],
		CASE WHEN @ifi = 0 AND mf.type = 0 THEN 'Instant File Initialization is disabled'
			WHEN @ifi = 1 AND mf.type = 0 THEN 'Instant File Initialization is enabled'
			ELSE '' END AS [Comments]
	FROM sys.master_files mf (NOLOCK)
	WHERE [database_id] = 2 AND [type] = 0
	GROUP BY mf.name, mf.[size], is_percent_growth, mf.growth, mf.type_desc, mf.[type]
	ORDER BY 3, 4
END
ELSE
BEGIN
	SELECT 'tempDB_files_Autogrow' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- NTFS block size in volumes that hold database files <> 64KB subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting NTFS block size in volumes that hold database files <> 64KB subsection', 10, 1) WITH NOWAIT
IF @allow_xpcmdshell = 1
BEGIN
	IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
		OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
			AND (SELECT COUNT(credential_id) FROM sys.credentials WHERE name = '##xp_cmdshell_proxy_account##') > 0) -- Is not sysadmin but proxy account exists
			AND (SELECT COUNT(l.name)
			FROM sys.server_permissions p JOIN sys.server_principals l 
			ON p.grantee_principal_id = l.principal_id
				AND p.class = 100 -- Server
				AND p.state IN ('G', 'W') -- Granted or Granted with Grant
				AND l.is_disabled = 0
				AND p.permission_name = 'ALTER SETTINGS'
				AND QUOTENAME(l.name) = QUOTENAME(USER_NAME())) = 0) -- Is not sysadmin but has alter settings permission
		OR ((ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) <> 1 
			AND ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_fileexist') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_instance_regread') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regread') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OAGetErrorInfo') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OACreate') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_OADestroy') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_cmdshell') > 0 AND
			(SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_regenumvalues') > 0)))
	BEGIN
		DECLARE @ntfs int
		DECLARE @pstbl_ntfs TABLE ([KeyExist] int)
		BEGIN TRY
			INSERT INTO @pstbl_ntfs
			EXEC master.sys.xp_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\PowerShell\1' -- check if Powershell is installed
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'NTFS block size in volumes that hold database files <> 64KB subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH

		SELECT @sao = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'show advanced options'
		SELECT @xcmd = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'xp_cmdshell'
		SELECT @ole = CAST([value] AS smallint) FROM sys.configurations WITH (NOLOCK) WHERE [name] = 'Ole Automation Procedures'

		RAISERROR ('  |-Configuration options set for NTFS Block size check', 10, 1) WITH NOWAIT
		IF @sao = 0
		BEGIN
			EXEC sp_configure 'show advanced options', 1; RECONFIGURE WITH OVERRIDE;
		END
		IF @xcmd = 0
		BEGIN
			EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE WITH OVERRIDE;
		END
		IF @ole = 0
		BEGIN
			EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE WITH OVERRIDE;
		END
		
		IF (SELECT [KeyExist] FROM @pstbl_ntfs) = 1
		BEGIN
			DECLARE @output_hw_tot_ntfs TABLE ([PS_OUTPUT] VARCHAR(2048));
			DECLARE @output_hw_format_ntfs TABLE ([volid] smallint IDENTITY(1,1), [HD_Volume] NVARCHAR(2048) NULL, [NTFS_Block] NVARCHAR(8) NULL)

			IF @custompath IS NULL
			BEGIN
				IF @sqlmajorver < 11
				BEGIN
					EXEC master..xp_instance_regread N'HKEY_LOCAL_MACHINE',N'Software\Microsoft\MSSQLServer\Setup',N'SQLPath', @path OUTPUT
					SET @path = @path + '\LOG'
				END
				ELSE
				BEGIN
					SET @sqlcmd = N'SELECT @pathOUT = LEFT([path], LEN([path])-1) FROM sys.dm_os_server_diagnostics_log_configurations';
					SET @params = N'@pathOUT NVARCHAR(2048) OUTPUT';
					EXECUTE sp_executesql @sqlcmd, @params, @pathOUT=@path OUTPUT;
				END

				-- Create COM object with FSO
				EXEC @OLEResult = master.dbo.sp_OACreate 'Scripting.FileSystemObject', @FSO OUT
				IF @OLEResult <> 0
				BEGIN
					EXEC sp_OAGetErrorInfo @FSO, @src OUT, @desc OUT
					SELECT @ErrorMessage = 'Error Creating COM Component 0x%x, %s, %s'
					RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
				END
				ELSE
				BEGIN
					EXEC @OLEResult = master.dbo.sp_OAMethod @FSO, 'FolderExists', @existout OUT, @path
					IF @OLEResult <> 0
					BEGIN
						EXEC sp_OAGetErrorInfo @FSO, @src OUT, @desc OUT
						SELECT @ErrorMessage = 'Error Calling FolderExists Method 0x%x, %s, %s'
						RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
					END
					ELSE
					BEGIN
						IF @existout <> 1
						BEGIN
							SET @path = CONVERT(NVARCHAR(500), SERVERPROPERTY('ErrorLogFileName'))
							SET @path = LEFT(@path,LEN(@path)-CHARINDEX('\', REVERSE(@path)))
						END 
					END
					EXEC @OLEResult = sp_OADestroy @FSO
				END
			END
			ELSE
			BEGIN
				SELECT @path = CASE WHEN @custompath LIKE '%\' THEN LEFT(@custompath, LEN(@custompath)-1) ELSE @custompath END
			END
			
			SET @FileName = @path + '\checkbp_ntfs_' + RTRIM(@server) + '.ps1'
				
			EXEC master.dbo.xp_fileexist @FileName, @existout out
			IF @existout = 0
			BEGIN -- Scan for local disks
				SET @Text1 = '[string] $serverName = ''localhost''
$vols = Get-WmiObject -computername $serverName -query "select name, blocksize from Win32_Volume where Capacity <> NULL and DriveType = 3"
foreach($vol in $vols)
{
[string] $drive = "{0}" -f $vol.name + ";" + $vol.blocksize
Write-Output $drive
} '
				EXEC @OLEResult = master.dbo.sp_OACreate 'Scripting.FileSystemObject', @FS OUT
				IF @OLEResult <> 0
				BEGIN
					EXEC sp_OAGetErrorInfo @FS, @src OUT, @desc OUT
					SELECT @ErrorMessage = 'Error Creating COM Component 0x%x, %s, %s'
					RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
				END

				--Open file
				EXEC @OLEResult = master.dbo.sp_OAMethod @FS, 'OpenTextFile', @FileID OUT, @FileName, 2, 1
				IF @OLEResult <> 0
				BEGIN
					EXEC sp_OAGetErrorInfo @FS, @src OUT, @desc OUT
					SELECT @ErrorMessage = 'Error Calling OpenTextFile Method 0x%x, %s, %s' + CHAR(10) + 'Could not create file ' + @FileName
					RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
				END
				ELSE
				BEGIN
					SELECT @ErrorMessage = '  |-Created file ' + @FileName
					RAISERROR (@ErrorMessage, 10, 1) WITH NOWAIT
				END

				--Write Text1
				EXEC @OLEResult = master.dbo.sp_OAMethod @FileID, 'WriteLine', NULL, @Text1
				IF @OLEResult <> 0
				BEGIN
					EXEC sp_OAGetErrorInfo @FS, @src OUT, @desc OUT
					SELECT @ErrorMessage = 'Error Calling WriteLine Method 0x%x, %s, %s' + CHAR(10) + 'Could not write to file ' + @FileName
					RAISERROR (@ErrorMessage, 16, 1, @OLEResult, @src, @desc);
				END

				EXEC @OLEResult = sp_OADestroy @FileID
				EXEC @OLEResult = sp_OADestroy @FS
			END
			ELSE
			BEGIN
				SELECT @ErrorMessage = '  |-Reusing file ' + @FileName
				RAISERROR (@ErrorMessage, 10, 1) WITH NOWAIT
			END
			
			SET @CMD = 'powershell -NoLogo -NoProfile -File "' + @FileName + '"'
			INSERT INTO @output_hw_tot_ntfs
			EXEC master.dbo.xp_cmdshell @CMD

			SET @CMD = 'del /Q "' + @FileName + '"'
			EXEC master.dbo.xp_cmdshell @CMD, NO_OUTPUT
		
			IF (SELECT COUNT([PS_OUTPUT]) 
			FROM @output_hw_tot_ntfs WHERE [PS_OUTPUT] LIKE '%cannot be loaded because%'
					OR [PS_OUTPUT] LIKE '%scripts is disabled%') = 0
			BEGIN
				INSERT INTO @output_hw_format_ntfs ([HD_Volume],[NTFS_Block])
				SELECT LEFT(RTRIM([PS_OUTPUT]), CASE WHEN CHARINDEX(';', RTRIM([PS_OUTPUT])) = 0 THEN LEN(RTRIM([PS_OUTPUT])) ELSE CHARINDEX(';', RTRIM([PS_OUTPUT]))-1 END),
					  RIGHT(RTRIM([PS_OUTPUT]), LEN(RTRIM([PS_OUTPUT]))-CASE WHEN CHARINDEX(';', RTRIM([PS_OUTPUT])) = 0 THEN LEN(RTRIM([PS_OUTPUT])) ELSE CHARINDEX(';', RTRIM([PS_OUTPUT])) END)
				FROM @output_hw_tot_ntfs
				WHERE [PS_OUTPUT] IS NOT NULL
			END
			ELSE
			BEGIN
				RAISERROR ('[WARNING: Powershell script cannot be loaded because the execution of scripts is disabled on this system.
To change the execution policy, type the following command in Powershell console: Set-ExecutionPolicy RemoteSigned
The Set-ExecutionPolicy cmdlet enables you to determine which Windows PowerShell scripts (if any) will be allowed to run on your computer. Windows PowerShell has four different execution policies:
	Restricted - No scripts can be run. Windows PowerShell can be used only in interactive mode.
	AllSigned - Only scripts signed by a trusted publisher can be run.
	RemoteSigned - Downloaded scripts must be signed by a trusted publisher before they can be run.
		|- REQUIRED by BP Check
	Unrestricted - No restrictions; all Windows PowerShell scripts can be run.]',16,1);	
			END
		
			SET @CMD2 = 'del ' + @FileName
			EXEC master.dbo.xp_cmdshell @CMD2, NO_OUTPUT;
		END
		ELSE
		BEGIN
			RAISERROR ('[WARNING: Powershell is not available. Bypassing NTFS block size check]',16,1);	
		END
			
		IF @xcmd = 0
		BEGIN
			EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE WITH OVERRIDE;
		END
		IF @ole = 0
		BEGIN
			EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE WITH OVERRIDE;
		END
		IF @sao = 0
		BEGIN
			EXEC sp_configure 'show advanced options', 0; RECONFIGURE WITH OVERRIDE;
		END;
			
		WITH ntfscte (physical_name, ntfsblock) AS (
			SELECT DISTINCT(LEFT(physical_name, LEN(t2.HD_Volume))), [NTFS_Block]
			FROM sys.master_files t1 INNER JOIN @output_hw_format_ntfs t2
			ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
			WHERE [database_id] <> 32767 AND (t2.[NTFS_Block] IS NOT NULL OR LEN(t2.[NTFS_Block]) > 0)
		)
		SELECT @ntfs = CASE WHEN (SELECT COUNT(*) FROM ntfscte) = 0 THEN NULL ELSE COUNT(cte1.[ntfsblock]) END
		FROM ntfscte cte1
		WHERE cte1.[ntfsblock] <> 65536;
		
		IF @ntfs > 0 AND @ntfs IS NOT NULL
		BEGIN
			SELECT 'NTFS_Block_Size' AS [Check], '[WARNING: Some volumes that hold database files are not formatted using the recommended NTFS block size of 64KB]' AS [Deviation]
			SELECT 'NTFS_Block_Size' AS [Information], t1.HD_Volume, (t1.[NTFS_Block]/1024) AS [NTFS_Block_Size_KB]
			FROM (SELECT DISTINCT(LEFT(physical_name, LEN(t2.HD_Volume))) AS [HD_Volume], [NTFS_Block]
				FROM sys.master_files t1 (NOLOCK) INNER JOIN @output_hw_format_ntfs t2
					ON LEFT(physical_name, LEN(t2.HD_Volume)) = t2.HD_Volume
					WHERE [database_id] <> 32767 AND (t2.[NTFS_Block] IS NOT NULL OR LEN(t2.[NTFS_Block]) > 0)) t1
			ORDER BY t1.HD_Volume OPTION (RECOMPILE);
		END
		ELSE IF @ntfs IS NULL
		BEGIN
			SELECT 'NTFS_Block_Size' AS [Check], '[WARNING: Could not gather information on NTFS block size]' AS [Deviation]
		END
		ELSE
		BEGIN
			SELECT 'NTFS_Block_Size' AS [Check], '[OK]' AS [Deviation]
		END;
	END
	ELSE
	BEGIN
		RAISERROR('[WARNING: Only a sysadmin can run the "NTFS block size" checks. A regular user can also run this check if a xp_cmdshell proxy account exists. Bypassing check]', 16, 1, N'xp_cmdshellproxy')
		RAISERROR('[WARNING: If not sysadmin, then must be a granted EXECUTE permissions on the following extended sprocs to run checks: sp_OACreate, sp_OADestroy, sp_OAGetErrorInfo, xp_cmdshell, xp_instance_regread, xp_regread, xp_fileexist and xp_regenumvalues. Bypassing check]', 16, 1, N'extended_sprocs')
		--RETURN
	END
	END
ELSE
BEGIN
	RAISERROR(' |- [INFORMATION: "NTFS block size" check was skipped because xp_cmdshell was not allowed.]', 10, 1, N'disallow_xp_cmdshell')
	--RETURN
END;

--------------------------------------------------------------------------------------------------------------------------------
-- VLF subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting VLF subsection', 10, 1) WITH NOWAIT
IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1
BEGIN
	DECLARE @query VARCHAR(1000)/*, @dbname VARCHAR(1000)*/, @count int, @count_used int, @logsize DECIMAL(20,1), @usedlogsize DECIMAL(20,1), @avgvlfsize DECIMAL(20,1)
	DECLARE @potsize DECIMAL(20,1), @n_iter int, @n_iter_final int, @initgrow DECIMAL(20,1), @n_init_iter int

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info1%')
	DROP TABLE #log_info1
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info1%')
	CREATE TABLE #log_info1 (dbname VARCHAR(100), 
		Actual_log_size_MB DECIMAL(20,1), 
		Used_Log_size_MB DECIMAL(20,1),
		Potential_log_size_MB DECIMAL(20,1), 
		Actual_VLFs int,
		Used_VLFs int,
		Avg_VLF_size_KB DECIMAL(20,1),
		Potential_VLFs int, 
		Growth_iterations int,
		Log_Initial_size_MB DECIMAL(20,1),
		File_autogrow_MB DECIMAL(20,1))
	
	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info2%')
	DROP TABLE #log_info2
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info2%')
	CREATE TABLE #log_info2 (dbname VARCHAR(100), 
		Actual_VLFs int, 
		VLF_size_KB DECIMAL(20,1), 
		growth_iteration int)

	DECLARE csr CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE is_read_only = 0 AND state = 0
	OPEN csr
	FETCH NEXT FROM csr INTO @dbname
	WHILE (@@FETCH_STATUS <> -1)
	BEGIN
		IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info3%')
		DROP TABLE #log_info3
		IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info3%')
		CREATE TABLE #log_info3 (recoveryunitid int NULL,
			fileid tinyint,
			file_size bigint,
			start_offset bigint,
			FSeqNo int,
			[status] tinyint,
			parity tinyint,
			create_lsn numeric(25,0))
		SET @query = 'DBCC LOGINFO (' + '''' + @dbname + ''') WITH NO_INFOMSGS'
		IF @sqlmajorver < 11
		BEGIN
			INSERT INTO #log_info3 (fileid, file_size, start_offset, FSeqNo, [status], parity, create_lsn)
			EXEC (@query)
		END
		ELSE
		BEGIN
			INSERT INTO #log_info3 (recoveryunitid, fileid, file_size, start_offset, FSeqNo, [status], parity, create_lsn)
			EXEC (@query)
		END

		SET @count = @@ROWCOUNT
		SET @count_used = (SELECT COUNT(fileid) FROM #log_info3 l WHERE l.[status] = 2)
		SET @logsize = (SELECT (MIN(l.start_offset) + SUM(l.file_size))/1048576.00 FROM #log_info3 l)
		SET @usedlogsize = (SELECT (MIN(l.start_offset) + SUM(CASE WHEN l.status <> 0 THEN l.file_size ELSE 0 END))/1048576.00 FROM #log_info3 l)
		SET @avgvlfsize = (SELECT AVG(l.file_size)/1024.00 FROM #log_info3 l)

		INSERT INTO #log_info2
		SELECT @dbname, COUNT(create_lsn), MIN(l.file_size)/1024.00,
			ROW_NUMBER() OVER(ORDER BY l.create_lsn) FROM #log_info3 l 
		GROUP BY l.create_lsn 
		ORDER BY l.create_lsn

		DROP TABLE #log_info3;

		-- Grow logs in MB instead of GB because of known issue prior to SQL 2012.
		-- More detail here: http://www.sqlskills.com/BLOGS/PAUL/post/Bug-log-file-growth-broken-for-multiples-of-4GB.aspx
		-- and http://connect.microsoft.com/SQLServer/feedback/details/481594/log-growth-not-working-properly-with-specific-growth-sizes-vlfs-also-not-created-appropriately
		-- or https://connect.microsoft.com/SQLServer/feedback/details/357502/transaction-log-file-size-will-not-grow-exactly-4gb-when-filegrowth-4gb
		IF @sqlmajorver >= 11
		BEGIN
			SET @n_iter = (SELECT CASE WHEN @logsize <= 64 THEN 1
				WHEN @logsize > 64 AND @logsize < 256 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/256, 0)
				WHEN @logsize >= 256 AND @logsize < 1024 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/512, 0)
				WHEN @logsize >= 1024 AND @logsize < 4096 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/1024, 0)
				WHEN @logsize >= 4096 AND @logsize < 8192 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/2048, 0)
				WHEN @logsize >= 8192 AND @logsize < 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/4096, 0)
				WHEN @logsize >= 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/8192, 0)
				END)
			SET @potsize = (SELECT CASE WHEN @logsize <= 64 THEN 1*64
				WHEN @logsize > 64 AND @logsize < 256 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/256, 0)*256
				WHEN @logsize >= 256 AND @logsize < 1024 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/512, 0)*512
				WHEN @logsize >= 1024 AND @logsize < 4096 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/1024, 0)*1024
				WHEN @logsize >= 4096 AND @logsize < 8192 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/2048, 0)*2048
				WHEN @logsize >= 8192 AND @logsize < 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/4096, 0)*4096
				WHEN @logsize >= 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/8192, 0)*8192
				END)
		END
		ELSE
		BEGIN
			SET @n_iter = (SELECT CASE WHEN @logsize <= 64 THEN 1
				WHEN @logsize > 64 AND @logsize < 256 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/256, 0)
				WHEN @logsize >= 256 AND @logsize < 1024 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/512, 0)
				WHEN @logsize >= 1024 AND @logsize < 4096 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/1024, 0)
				WHEN @logsize >= 4096 AND @logsize < 8192 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/2048, 0)
				WHEN @logsize >= 8192 AND @logsize < 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/4000, 0)
				WHEN @logsize >= 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/8000, 0)
				END)
			SET @potsize = (SELECT CASE WHEN @logsize <= 64 THEN 1*64
				WHEN @logsize > 64 AND @logsize < 256 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/256, 0)*256
				WHEN @logsize >= 256 AND @logsize < 1024 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/512, 0)*512
				WHEN @logsize >= 1024 AND @logsize < 4096 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/1024, 0)*1024
				WHEN @logsize >= 4096 AND @logsize < 8192 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/2048, 0)*2048
				WHEN @logsize >= 8192 AND @logsize < 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/4000, 0)*4000
				WHEN @logsize >= 16384 THEN ROUND(CONVERT(FLOAT, ROUND(@logsize, -2))/8000, 0)*8000
				END)
		END
		
		-- If the proposed log size is smaller than current log, and also smaller than 4GB,
		-- and there is less than 512MB of diff between the current size and proposed size, add 1 grow.
		SET @n_iter_final = @n_iter
		IF @logsize > @potsize AND @potsize <= 4096 AND ABS(@logsize - @potsize) < 512
		BEGIN
			SET @n_iter_final = @n_iter + 1
		END
		-- If the proposed log size is larger than current log, and also larger than 50GB, 
		-- and there is less than 1GB of diff between the current size and proposed size, take 1 grow.
		ELSE IF @logsize < @potsize AND @potsize <= 51200 AND ABS(@logsize - @potsize) > 1024
		BEGIN
			SET @n_iter_final = @n_iter - 1
		END

		IF @potsize = 0 
		BEGIN 
			SET @potsize = 64 
		END
		IF @n_iter = 0 
		BEGIN 
			SET @n_iter = 1
		END
		
		SET @potsize = (SELECT CASE WHEN @n_iter < @n_iter_final THEN @potsize + (@potsize/@n_iter) 
				WHEN @n_iter > @n_iter_final THEN @potsize - (@potsize/@n_iter) 
				ELSE @potsize END)
		
		SET @n_init_iter = @n_iter_final
		IF @potsize >= 8192
		BEGIN
			SET @initgrow = @potsize/@n_iter_final
		END
		IF @potsize >= 64 AND @potsize <= 512
		BEGIN
			SET @n_init_iter = 1
			SET @initgrow = 512
		END
		IF @potsize > 512 AND @potsize <= 1024
		BEGIN
			SET @n_init_iter = 1
			SET @initgrow = 1023
		END
		IF @potsize > 1024 AND @potsize < 8192
		BEGIN
			SET @n_init_iter = 1
			SET @initgrow = @potsize
		END

		INSERT INTO #log_info1
		VALUES(@dbname, @logsize, @usedlogsize, @potsize, @count, @count_used, @avgvlfsize, 
			CASE WHEN @potsize <= 64 THEN (@potsize/(@potsize/@n_init_iter))*4
				WHEN @potsize > 64 AND @potsize < 1024 THEN (@potsize/(@potsize/@n_init_iter))*8
				WHEN @potsize >= 1024 THEN (@potsize/(@potsize/@n_init_iter))*16
				END,
			@n_init_iter, @initgrow, 
			CASE WHEN (@potsize/@n_iter_final) <= 1024 THEN (@potsize/@n_iter_final) ELSE 1024 END
			);

		FETCH NEXT FROM csr INTO @dbname

	END
	CLOSE csr
	DEALLOCATE csr;

	IF (SELECT COUNT(dbname) FROM #log_info1 WHERE Actual_VLFs >= 50) > 0
	BEGIN
		SELECT 'Virtual_Log_Files' AS [Check], '[WARNING: Some user databases have many VLFs. Please review these]' AS [Deviation]
		SELECT 'Virtual_Log_Files' AS [Information], dbname AS [Database_Name], Actual_log_size_MB, Used_Log_size_MB,
			Potential_log_size_MB, Actual_VLFs, Used_VLFs, Potential_VLFs, Growth_iterations, Log_Initial_size_MB, File_autogrow_MB
		FROM #log_info1
		WHERE Actual_VLFs >= 50 -- My rule of thumb is 50 VLFs. Your mileage may vary.
		ORDER BY dbname;
		
		SELECT 'Virtual_Log_Files_per_growth' AS [Information], #log_info2.dbname AS [Database_Name], #log_info2.Actual_VLFs AS VLFs_remain_per_spawn, VLF_size_KB, growth_iteration
		FROM #log_info2
		INNER JOIN #log_info1 ON #log_info2.dbname = #log_info1.dbname
		WHERE #log_info1.Actual_VLFs >= 50 -- My rule of thumb is 50 VLFs. Your mileage may vary.
		ORDER BY #log_info2.dbname, growth_iteration

		SELECT 'Virtual_Log_Files_agg_per_size' AS [Information], #log_info2.dbname AS [Database_Name], SUM(#log_info2.Actual_VLFs) AS VLFs_per_size, VLF_size_KB
		FROM #log_info2
		INNER JOIN #log_info1 ON #log_info2.dbname = #log_info1.dbname
		WHERE #log_info1.Actual_VLFs >= 50 -- My rule of thumb is 50 VLFs. Your mileage may vary.
		GROUP BY #log_info2.dbname, VLF_size_KB
		ORDER BY #log_info2.dbname, VLF_size_KB DESC
	END
	ELSE
	BEGIN
		SELECT 'Virtual_Log_Files' AS [Check], '[OK]' AS [Deviation]
	END
END
ELSE
BEGIN
	RAISERROR('[WARNING: Only a sysadmin can run the "VLF" check. Bypassing check]', 16, 1, N'sysadmin')
	--RETURN
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Perf counters, Waits and Latches subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Perf counters, Waits and Latches subsection (wait for 90s)', 10, 1) WITH NOWAIT
DECLARE @minctr DATETIME, @maxctr DATETIME
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblPerfCount%')
DROP TABLE #tblPerfCount
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblPerfCount%')
CREATE TABLE #tblPerfCount (
	[retrieval_time] [datetime],
	[object_name] [NVARCHAR](128),
	[counter_name] [NVARCHAR](128),
	[instance_name] [NVARCHAR](128),
	[counter_name_type] int,
	[cntr_value] float NULL
	);
		
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblWaits%')
DROP TABLE #tblWaits
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblWaits%')
CREATE TABLE [dbo].[#tblWaits](
	[retrieval_time] [datetime],
	[wait_type] [nvarchar](60) NOT NULL,
	[wait_time_ms] bigint NULL,
	[signal_wait_time_ms] bigint NULL,
	[resource_wait_time_ms] bigint NULL
	);

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFinalWaits%')
DROP TABLE #tblFinalWaits
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFinalWaits%')
CREATE TABLE [dbo].[#tblFinalWaits](
	[wait_type] [nvarchar](60) NOT NULL,
	[wait_time_s] [numeric](16, 6) NULL,
	[signal_wait_time_s] [numeric](16, 6) NULL,
	[resource_wait_time_s] [numeric](16, 6) NULL,
	[pct] [numeric](12, 2) NULL,
	[rn] [bigint] NULL,
	[signal_wait_pct] [numeric](12, 2) NULL,
	[resource_wait_pct] [numeric](12, 2) NULL
	);
		
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblLatches%')
DROP TABLE #tblLatches
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblLatches%')
CREATE TABLE [dbo].[#tblLatches](
	[retrieval_time] [datetime],
	[latch_class] [nvarchar](60) NOT NULL,
	[wait_time_ms] bigint NULL,
	[waiting_requests_count] [bigint] NULL
	);
		
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFinalLatches%')
DROP TABLE #tblFinalLatches
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFinalLatches%')
CREATE TABLE [dbo].[#tblFinalLatches](
	[latch_class] [nvarchar](60) NOT NULL,
	[wait_time_s] [decimal](16, 6) NULL,
	[waiting_requests_count] [bigint] NULL,
	[pct] [decimal](12, 2) NULL,
	[rn] [bigint] NULL
	);
		
SELECT @minctr = GETDATE()

-- When counter type = 272696576 (find delta from two collection points)
-- When counter type = 65792 (face value of just one collection point)
-- When counter type = 1073874176 (find delta from current value and base value, between two collection points). Base value is counter with type 1073939712.
-- When counter type = 537003264 (find delta from current value and base value, in just one collection point). Base value is counter with type 1073939712.

INSERT INTO #tblPerfCount
SELECT @minctr, [object_name], counter_name, instance_name, cntr_type AS counter_name_type, cntr_value
FROM sys.dm_os_performance_counters pc0 (NOLOCK)
WHERE ([object_name] LIKE '%:Access Methods%'
		OR [object_name] LIKE '%:Buffer Manager%'
		OR [object_name] LIKE '%:Buffer Node%'
		OR [object_name] LIKE '%:Latches%'
		OR [object_name] LIKE '%:Locks%'
		OR [object_name] LIKE '%:Memory Manager%'
		OR [object_name] LIKE '%:Memory Node%'
		OR [object_name] LIKE '%:Plan Cache%'
		OR [object_name] LIKE '%:SQL Statistics%'
		OR [object_name] LIKE '%:Wait Statistics%'
		OR [object_name] LIKE '%:Workload Group Stats%'
		OR [object_name] LIKE '%:Batch Resp Statistics%') 
	AND (counter_name LIKE '%FreeSpace Scans/sec%'
		OR counter_name LIKE '%Forwarded Records/sec%'
		OR counter_name LIKE '%Full Scans/sec%'
		OR counter_name LIKE '%Index Searches/sec%'
		OR counter_name LIKE '%Page Splits/sec%'
		OR counter_name LIKE '%Scan Point Revalidations/sec%'
		OR counter_name LIKE '%Table Lock Escalations/sec%'
		OR counter_name LIKE '%Workfiles Created/sec%'
		OR counter_name LIKE '%Worktables Created/sec%'
		OR counter_name LIKE '%Buffer cache hit ratio%'
		OR counter_name LIKE '%Buffer cache hit ratio base%'
		OR counter_name LIKE '%Checkpoint pages/sec%'  
		OR counter_name LIKE '%Lazy writes/sec%'
		OR counter_name LIKE '%Free pages%'     
		OR counter_name LIKE '%Page life expectancy%'  
		OR counter_name LIKE '%Page lookups/sec%'      
		OR counter_name LIKE '%Average Latch Wait Time (ms)%'
		OR counter_name LIKE '%Average Latch Wait Time Base%'
		OR counter_name LIKE '%Average Wait Time (ms)%'
		OR counter_name LIKE '%Average Wait Time Base%'
		OR counter_name LIKE '%Number of Deadlocks/sec%'
		OR counter_name LIKE '%Stolen Server Memory (KB)%'                                                                                              
		OR counter_name LIKE '%Target Server Memory (KB)%'
		OR counter_name LIKE '%Total Server Memory (KB)%'
		OR counter_name LIKE '%Foreign Node Memory (KB)%'
		OR counter_name LIKE '%Stolen Node Memory (KB)%'
		OR counter_name LIKE '%Target Node Memory (KB)%'
		OR counter_name LIKE '%Total Node Memory (KB)%'
		OR counter_name LIKE '%Batch Requests/sec%'
		OR counter_name LIKE '%SQL Compilations/sec%'  
		OR counter_name LIKE '%SQL Re-Compilations/sec%'
		OR counter_name LIKE '%Lock waits%'
		OR counter_name LIKE '%Log buffer waits%'      
		OR counter_name LIKE '%Log write waits%'       
		OR counter_name LIKE '%Memory grant queue waits%'
		OR counter_name LIKE '%Network IO waits%'      
		OR counter_name LIKE '%Non-Page latch waits%'  
		OR counter_name LIKE '%Page IO latch waits%'   
		OR counter_name LIKE '%Page latch waits%'      
		OR counter_name LIKE '%Active parallel threads%'
		OR counter_name LIKE '%Blocked tasks%'         
		OR counter_name LIKE '%CPU usage %'           
		OR counter_name LIKE '%CPU usage % base%'      
		OR counter_name LIKE '%Query optimizations/sec%'
		OR counter_name LIKE '%Requests completed/sec%'
		OR counter_name LIKE '%Suboptimal plans/sec%'
		OR counter_name LIKE '%Temporary Tables & Table Variables%'
		OR counter_name LIKE '%Extended Stored Procedures%'
		OR counter_name LIKE '%Bound Trees%'           
		OR counter_name LIKE '%SQL Plans%'             
		OR counter_name LIKE '%Object Plans%'          
		OR counter_name LIKE '%_Total%'
		OR counter_name LIKE 'Batches%');

INSERT INTO #tblWaits
SELECT @minctr, wait_type, wait_time_ms, signal_wait_time_ms,(wait_time_ms-signal_wait_time_ms) AS resource_wait_time_ms
FROM sys.dm_os_wait_stats (NOLOCK)
WHERE wait_type NOT IN ('RESOURCE_QUEUE', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP',
	'LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH','XE_TIMER_EVENT','BROKER_TASK_STOP','CLR_MANUAL_EVENT',
	'CLR_AUTO_EVENT','DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT','BROKER_TO_FLUSH',
	'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'MSQL_XP', 'WAIT_FOR_RESULTS', 'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'SLEEP_TASK',
	'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH', 'WAITFOR', 'BROKER_EVENTHANDLER', 'TRACEWRITE', 'FT_IFTSHC_MUTEX', 'BROKER_RECEIVE_WAITFOR', 
	'ONDEMAND_TASK_QUEUE', 'DBMIRROR_EVENTS_QUEUE', 'DBMIRRORING_CMD', 'BROKER_TRANSMITTER', 'SQLTRACE_WAIT_ENTRIES', 'SLEEP_BPOOL_FLUSH', 'SQLTRACE_LOCK',
	'DIRTY_PAGE_POLL', 'HADR_FILESTREAM_IOMGR_IOCOMPLETION', 'SP_SERVER_DIAGNOSTICS_SLEEP') 
	AND wait_type NOT LIKE N'SLEEP_%'
	AND wait_time_ms > 0;		

INSERT INTO #tblLatches
SELECT @minctr, latch_class, wait_time_ms, waiting_requests_count
FROM sys.dm_os_latch_stats (NOLOCK)
WHERE /*latch_class NOT IN ('BUFFER')
	AND*/ wait_time_ms > 0;

WAITFOR DELAY '00:01:30';

SELECT @maxctr = GETDATE()
		
INSERT INTO #tblPerfCount
SELECT @maxctr, [object_name], counter_name, instance_name, cntr_type AS counter_name_type, cntr_value
FROM sys.dm_os_performance_counters pc0 (NOLOCK)
WHERE (cntr_type = 272696576 OR cntr_type = 1073874176 OR cntr_type = 1073939712) -- Get only counters whose delta matters
	AND ([object_name] LIKE '%:Access Methods%'
		OR [object_name] LIKE '%:Buffer Manager%'
		OR [object_name] LIKE '%:Buffer Node%'
		OR [object_name] LIKE '%:Latches%'
		OR [object_name] LIKE '%:Locks%'
		OR [object_name] LIKE '%:Memory Manager%'
		OR [object_name] LIKE '%:Memory Node%'
		OR [object_name] LIKE '%:Plan Cache%'
		OR [object_name] LIKE '%:SQL Statistics%'
		OR [object_name] LIKE '%:Wait Statistics%'
		OR [object_name] LIKE '%:Workload Group Stats%') 
	AND (counter_name LIKE '%FreeSpace Scans/sec%'
		OR counter_name LIKE '%Forwarded Records/sec%'
		OR counter_name LIKE '%Full Scans/sec%'
		OR counter_name LIKE '%Index Searches/sec%'
		OR counter_name LIKE '%Page Splits/sec%'
		OR counter_name LIKE '%Scan Point Revalidations/sec%'
		OR counter_name LIKE '%Table Lock Escalations/sec%'
		OR counter_name LIKE '%Workfiles Created/sec%'
		OR counter_name LIKE '%Worktables Created/sec%'
		OR counter_name LIKE '%Buffer cache hit ratio%'
		OR counter_name LIKE '%Buffer cache hit ratio base%'
		OR counter_name LIKE '%Checkpoint pages/sec%'  
		OR counter_name LIKE '%Lazy writes/sec%'
		OR counter_name LIKE '%Free pages%'     
		OR counter_name LIKE '%Page life expectancy%'  
		OR counter_name LIKE '%Page lookups/sec%'      
		OR counter_name LIKE '%Average Latch Wait Time (ms)%'
		OR counter_name LIKE '%Average Latch Wait Time Base%'
		OR counter_name LIKE '%Average Wait Time (ms)%'
		OR counter_name LIKE '%Average Wait Time Base%'
		OR counter_name LIKE '%Number of Deadlocks/sec%'
		OR counter_name LIKE '%Stolen Server Memory (KB)%'                                                                                              
		OR counter_name LIKE '%Target Server Memory (KB)%'
		OR counter_name LIKE '%Total Server Memory (KB)%'
		OR counter_name LIKE '%Foreign Node Memory (KB)%'
		OR counter_name LIKE '%Stolen Node Memory (KB)%'
		OR counter_name LIKE '%Target Node Memory (KB)%'
		OR counter_name LIKE '%Total Node Memory (KB)%'
		OR counter_name LIKE '%Batch Requests/sec%'
		OR counter_name LIKE '%SQL Compilations/sec%'  
		OR counter_name LIKE '%SQL Re-Compilations/sec%'
		OR counter_name LIKE '%Lock waits%'
		OR counter_name LIKE '%Log buffer waits%'      
		OR counter_name LIKE '%Log write waits%'       
		OR counter_name LIKE '%Memory grant queue waits%'
		OR counter_name LIKE '%Network IO waits%'      
		OR counter_name LIKE '%Non-Page latch waits%'  
		OR counter_name LIKE '%Page IO latch waits%'   
		OR counter_name LIKE '%Page latch waits%'      
		OR counter_name LIKE '%Active parallel threads%'
		OR counter_name LIKE '%Blocked tasks%'         
		OR counter_name LIKE '%CPU usage %'           
		OR counter_name LIKE '%CPU usage % base%'      
		OR counter_name LIKE '%Query optimizations/sec%'
		OR counter_name LIKE '%Requests completed/sec%'
		OR counter_name LIKE '%Suboptimal plans/sec%'
		OR counter_name LIKE '%Temporary Tables & Table Variables%'
		OR counter_name LIKE '%Extended Stored Procedures%'
		OR counter_name LIKE '%Bound Trees%'           
		OR counter_name LIKE '%SQL Plans%'             
		OR counter_name LIKE '%Object Plans%'          
		OR counter_name LIKE '%_Total%');
			
INSERT INTO #tblWaits
SELECT @maxctr, wait_type, wait_time_ms, signal_wait_time_ms,(wait_time_ms-signal_wait_time_ms) AS resource_wait_time_ms
FROM sys.dm_os_wait_stats (NOLOCK)
WHERE wait_type NOT IN ('RESOURCE_QUEUE', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP',
	'LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH','XE_TIMER_EVENT','BROKER_TASK_STOP','CLR_MANUAL_EVENT',
	'CLR_AUTO_EVENT','DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT','BROKER_TO_FLUSH',
	'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'MSQL_XP', 'WAIT_FOR_RESULTS', 'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'SLEEP_TASK',
	'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH', 'WAITFOR', 'BROKER_EVENTHANDLER', 'TRACEWRITE', 'FT_IFTSHC_MUTEX', 'BROKER_RECEIVE_WAITFOR', 
	'ONDEMAND_TASK_QUEUE', 'DBMIRROR_EVENTS_QUEUE', 'DBMIRRORING_CMD', 'BROKER_TRANSMITTER', 'SQLTRACE_WAIT_ENTRIES', 'SLEEP_BPOOL_FLUSH', 'SQLTRACE_LOCK',
	'DIRTY_PAGE_POLL', 'HADR_FILESTREAM_IOMGR_IOCOMPLETION', 'SP_SERVER_DIAGNOSTICS_SLEEP') 
	AND wait_type NOT LIKE N'SLEEP_%'
	AND wait_time_ms > 0;

INSERT INTO #tblLatches
SELECT @maxctr, latch_class, wait_time_ms, waiting_requests_count
FROM sys.dm_os_latch_stats (NOLOCK)
WHERE /*latch_class NOT IN ('BUFFER')
	AND*/ wait_time_ms > 0;

SELECT 'Perf_Counters' AS [Check], '[INFORMATION: Perf Counter values are provided as reference only. If one or more is abnormal, please investigate further]' AS [Deviation]
;WITH ctePerfCount1 ([object_name],counter_name,instance_name,counter_name_type,cntr_value) AS (SELECT [object_name],counter_name,instance_name,counter_name_type,cntr_value FROM #tblPerfCount WHERE [retrieval_time] = @minctr),
	ctePerfCount2 ([object_name],counter_name,instance_name,counter_name_type,cntr_value) AS (SELECT [object_name],counter_name,instance_name,counter_name_type,cntr_value FROM #tblPerfCount WHERE [retrieval_time] = @maxctr)
SELECT DISTINCT 'Perf_Counters' AS [Information], t1.[object_name] AS Counter_family, t1.counter_name AS Counter_name, t1.instance_name AS Counter_instance,
	CASE WHEN t1.counter_name_type = 272696576
		THEN CONVERT(decimal(20,3),(
		(SELECT t2.cntr_value FROM ctePerfCount2 t2 WHERE t2.counter_name = t1.counter_name AND t2.instance_name = t1.instance_name) -
		(SELECT t2.cntr_value FROM ctePerfCount1 t2 WHERE t2.counter_name = t1.counter_name AND t2.instance_name = t1.instance_name)
		) / DATEDIFF(ss,@minctr,@maxctr)) -- Get value per s over last 90s
	WHEN t1.counter_name_type = 537003264
		THEN (SELECT CONVERT(decimal(20,3),(t2.cntr_value / t3.cntr_value) * 100.0)
				FROM ctePerfCount1 t2 INNER JOIN ctePerfCount1 t3 ON t2.[object_name] = t3.[object_name] AND t2.instance_name = t3.instance_name AND RTRIM(t2.counter_name) + N' base' = t3.counter_name
				WHERE t2.counter_name_type = t1.counter_name_type AND t2.counter_name = t1.counter_name AND t2.instance_name = t1.instance_name
				GROUP BY t2.cntr_value, t3.cntr_value, t2.counter_name)
	WHEN t1.counter_name_type = 1073874176 AND t1.counter_name = 'Average Latch Wait Time (ms)'
		THEN CONVERT(decimal(20,3),(
		(
		(SELECT t2.cntr_value - t3.cntr_value FROM ctePerfCount2 t2 INNER JOIN ctePerfCount1 t3 ON t2.[object_name] = t3.[object_name] AND t2.counter_name = t3.counter_name
		WHERE t2.counter_name = t1.counter_name /*AND t2.counter_name_type = t1.counter_name_type AND t2.instance_name = t1.instance_name*/
		GROUP BY t2.cntr_value, t3.cntr_value, t2.counter_name)
		-
		(SELECT t2.cntr_value - t3.cntr_value FROM ctePerfCount2 t2 INNER JOIN ctePerfCount1 t3 ON t2.[object_name] = t3.[object_name] AND t2.counter_name = t3.counter_name
		WHERE t2.counter_name = 'Average Latch Wait Time Base' AND t2.instance_name = t1.instance_name
		GROUP BY t2.cntr_value, t3.cntr_value, t2.counter_name)
		)
		/ DATEDIFF(ss,@minctr,@maxctr))) -- Get value per s over last 90s
	WHEN t1.counter_name_type = 1073874176 AND t1.counter_name = 'Average Wait Time (ms)'
		THEN CONVERT(decimal(20,3),(
		(
		SELECT t4.cntr_value - t5.cntr_value
		FROM
		(SELECT t2.cntr_value - t3.cntr_value AS cntr_value, t2.instance_name FROM ctePerfCount2 t2 INNER JOIN ctePerfCount1 t3 ON t2.[object_name] = t3.[object_name] AND t2.counter_name = t3.counter_name AND t2.instance_name = t3.instance_name 
		WHERE t2.counter_name = t1.counter_name AND t2.counter_name_type = t1.counter_name_type AND t2.instance_name = t1.instance_name
		GROUP BY t2.cntr_value, t3.cntr_value, t2.counter_name, t2.instance_name) AS t4
		INNER JOIN 
		(SELECT t2.cntr_value - t3.cntr_value AS cntr_value, t2.instance_name FROM ctePerfCount2 t2 INNER JOIN ctePerfCount1 t3 ON t2.[object_name] = t3.[object_name] AND t2.counter_name = t3.counter_name AND t2.instance_name = t3.instance_name 
		WHERE t2.counter_name = 'Average Wait Time Base' AND t2.instance_name = t1.instance_name
		GROUP BY t2.cntr_value, t3.cntr_value, t2.counter_name, t2.instance_name) AS t5
		ON t4.instance_name = t5.instance_name
		)
		/ DATEDIFF(ss,@minctr,@maxctr))) -- Get value per s over last 90s
	ELSE CONVERT(decimal(20,3),t1.cntr_value)
END AS Counter_value_last_90s
FROM ctePerfCount1 t1
WHERE (t1.counter_name_type <> 1073939712)
GROUP BY t1.[object_name], t1.[counter_name], t1.instance_name, t1.counter_name_type, t1.cntr_value
ORDER BY t1.[object_name], t1.[counter_name], t1.instance_name;
	
IF @sqlmajorver >= 11
BEGIN
	SELECT 'Perf_Counters' AS [Information], [counter_name] AS Counter_name, "CPU Time:Total(ms)", "CPU Time:Requests", "Elapsed Time:Total(ms)", "Elapsed Time:Requests"
	FROM (SELECT [counter_name],[instance_name],[cntr_value] FROM #tblPerfCount WHERE [object_name] LIKE '%Batch Resp Statistics%') AS pc
	PIVOT(AVG([cntr_value]) FOR [instance_name]
	IN ("CPU Time:Total(ms)", "CPU Time:Requests", "Elapsed Time:Total(ms)", "Elapsed Time:Requests")
	) AS Pvt;
END

;WITH cteWaits1 (wait_type,wait_time_ms,signal_wait_time_ms,resource_wait_time_ms) AS (SELECT wait_type,wait_time_ms,signal_wait_time_ms,resource_wait_time_ms FROM #tblWaits WHERE [retrieval_time] = @minctr),
	cteWaits2 (wait_type,wait_time_ms,signal_wait_time_ms,resource_wait_time_ms) AS (SELECT wait_type,wait_time_ms,signal_wait_time_ms,resource_wait_time_ms FROM #tblWaits WHERE [retrieval_time] = @maxctr)
INSERT INTO #tblFinalWaits
SELECT DISTINCT t1.wait_type, (t2.wait_time_ms-t1.wait_time_ms) / 1000. AS wait_time_s,
	(t2.signal_wait_time_ms-t1.signal_wait_time_ms) / 1000. AS signal_wait_time_s,
	((t2.wait_time_ms-t2.signal_wait_time_ms)-(t1.wait_time_ms-t1.signal_wait_time_ms)) / 1000. AS resource_wait_time_s,
	100.0 * (t2.wait_time_ms-t1.wait_time_ms) / SUM(t2.wait_time_ms-t1.wait_time_ms) OVER() AS pct,
	ROW_NUMBER() OVER(ORDER BY (t2.wait_time_ms-t1.wait_time_ms) DESC) AS rn,
	SUM(t2.signal_wait_time_ms-t1.signal_wait_time_ms) * 1.0 / SUM(t2.wait_time_ms-t1.wait_time_ms) * 100 AS signal_wait_pct,
	(SUM(t2.wait_time_ms-t2.signal_wait_time_ms)-SUM(t1.wait_time_ms-t1.signal_wait_time_ms)) * 1.0 / (SUM(t2.wait_time_ms)-SUM(t1.wait_time_ms)) * 100 AS resource_wait_pct
FROM cteWaits1 t1 INNER JOIN cteWaits2 t2 ON t1.wait_type = t2.wait_type
GROUP BY t1.wait_type, t1.wait_time_ms, t1.signal_wait_time_ms, t1.resource_wait_time_ms, t2.wait_time_ms, t2.signal_wait_time_ms, t2.resource_wait_time_ms
HAVING (t2.wait_time_ms-t1.wait_time_ms) > 0
ORDER BY wait_time_s DESC;

SELECT 'Waits_Last_90s' AS [Information], W1.wait_type, 
	CAST(W1.wait_time_s AS DECIMAL(12, 2)) AS wait_time_s,
	CAST(W1.signal_wait_time_s AS DECIMAL(12, 2)) AS signal_wait_time_s,
	CAST(W1.resource_wait_time_s AS DECIMAL(12, 2)) AS resource_wait_time_s,
	CAST(W1.pct AS DECIMAL(12, 2)) AS pct,
	CAST(SUM(W2.pct) AS DECIMAL(12, 2)) AS overall_running_pct,
	CAST(W1.signal_wait_pct AS DECIMAL(12, 2)) AS signal_wait_pct,
	CAST(W1.resource_wait_pct AS DECIMAL(12, 2)) AS resource_wait_pct,
	CASE WHEN W1.wait_type LIKE N'LCK_%' OR W1.wait_type = N'LOCK' THEN N'Lock'
		WHEN W1.wait_type LIKE N'LATCH_%' THEN N'Latch'
		WHEN W1.wait_type LIKE N'PAGELATCH_%' THEN N'Buffer Latch'
		WHEN W1.wait_type LIKE N'PAGEIOLATCH_%' THEN N'Buffer IO'
		WHEN W1.wait_type LIKE N'HADR_SYNC_COMMIT' THEN N'AlwaysOn - Secondary Synch' 
		WHEN W1.wait_type LIKE N'HADR_%' THEN N'AlwaysOn'
		WHEN W1.wait_type LIKE N'FFT_%' THEN N'FileTable'
		WHEN W1.wait_type LIKE N'PREEMPTIVE_%' THEN N'External APIs or XPs' -- Used to indicate a worker is running code that is not under the SQLOS Scheduling;
		WHEN W1.wait_type IN (N'IO_COMPLETION', N'ASYNC_IO_COMPLETION', /*N'HADR_FILESTREAM_IOMGR_IOCOMPLETION',*/ N'DISKIO_SUSPEND') THEN N'Other IO'
		WHEN W1.wait_type IN(N'BACKUPIO', N'BACKUPBUFFER') THEN 'Backup IO'
		WHEN W1.wait_type = N'THREADPOOL' THEN 'CPU - Unavailable Worker Threads'
		WHEN W1.wait_type = N'SOS_SCHEDULER_YIELD' THEN N'CPU - Scheduler Yielding'
		WHEN W1.wait_type IN (N'CXPACKET', N'EXCHANGE') THEN N'CPU - Parallelism'
		WHEN W1.wait_type IN (N'LOGMGR', N'LOGBUFFER', N'LOGMGR_RESERVE_APPEND', N'LOGMGR_FLUSH', N'WRITELOG') THEN N'Logging'
		WHEN W1.wait_type IN (N'NET_WAITFOR_PACKET',N'NETWORK_IO') THEN N'Network IO'
		WHEN W1.wait_type = N'ASYNC_NETWORK_IO' THEN N'Client Network IO'
		WHEN W1.wait_type IN (N'RESOURCE_SEMAPHORE_SMALL_QUERY',N'UTIL_PAGE_ALLOC',N'SOS_VIRTUALMEMORY_LOW',N'RESOURCE_SEMAPHORE', N'CMEMTHREAD', N'SOS_RESERVEDMEMBLOCKLIST') THEN N'Memory' 
		WHEN W1.wait_type LIKE N'CLR_%' OR W1.wait_type LIKE N'SQLCLR%' THEN N'CLR'
		WHEN W1.wait_type LIKE N'DBMIRROR%' OR W1.wait_type = N'MIRROR_SEND_MESSAGE' THEN N'Mirroring'
		WHEN W1.wait_type LIKE N'RESOURCE_SEMAPHORE_%' OR W1.wait_type LIKE N'RESOURCE_SEMAPHORE_QUERY_COMPILE' THEN N'Compilation' 
		WHEN W1.wait_type LIKE N'XACT%' OR W1.wait_type LIKE N'DTC_%' OR W1.wait_type LIKE N'TRAN_MARKLATCH_%' OR W1.wait_type LIKE N'MSQL_XACT_%' OR W1.wait_type = N'TRANSACTION_MUTEX' THEN N'Transaction'
	--	WHEN W1.wait_type LIKE N'SLEEP_%' OR W1.wait_type IN(N'LAZYWRITER_SLEEP', N'SQLTRACE_BUFFER_FLUSH', N'WAITFOR', N'WAIT_FOR_RESULTS', N'SQLTRACE_INCREMENTAL_FLUSH_SLEEP', N'SLEEP_TASK', N'SLEEP_SYSTEMTASK') THEN N'Sleep'
		WHEN W1.wait_type LIKE N'FT_%' THEN N'Full Text'
	ELSE N'Other' END AS 'wait_category'
FROM #tblFinalWaits AS W1 INNER JOIN #tblFinalWaits AS W2 ON W2.rn <= W1.rn
GROUP BY W1.rn, W1.wait_type, W1.wait_time_s, W1.pct, W1.signal_wait_time_s, W1.resource_wait_time_s, W1.signal_wait_pct, W1.resource_wait_pct
HAVING W1.wait_time_s >= 0.01 AND (SUM(W2.pct)-W1.pct) < 100  -- percentage threshold
ORDER BY W1.rn; 

;WITH Waits AS
(SELECT wait_type, wait_time_ms / 1000. AS wait_time_s,
	signal_wait_time_ms / 1000. AS signal_wait_time_s,
	(wait_time_ms-signal_wait_time_ms) / 1000. AS resource_wait_time_s,
	SUM(signal_wait_time_ms) * 1.0 / SUM(wait_time_ms) * 100 AS signal_wait_pct,
	SUM(wait_time_ms-signal_wait_time_ms) * 1.0 / SUM(wait_time_ms) * 100 AS resource_wait_pct,
	100.0 * wait_time_ms / SUM(wait_time_ms) OVER() AS pct,
	ROW_NUMBER() OVER(ORDER BY wait_time_ms DESC) AS rn
	FROM sys.dm_os_wait_stats
	WHERE wait_type NOT IN ('RESOURCE_QUEUE', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP'
	, 'LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH','XE_TIMER_EVENT','BROKER_TASK_STOP','CLR_MANUAL_EVENT'
	,'CLR_AUTO_EVENT','DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT','BROKER_TO_FLUSH'
	,'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'MSQL_XP', 'WAIT_FOR_RESULTS', 'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'SLEEP_TASK',
	'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH', 'WAITFOR', 'BROKER_EVENTHANDLER', 'TRACEWRITE', 'FT_IFTSHC_MUTEX', 'BROKER_RECEIVE_WAITFOR', 
	'ONDEMAND_TASK_QUEUE', 'DBMIRROR_EVENTS_QUEUE', 'DBMIRRORING_CMD', 'BROKER_TRANSMITTER', 'SQLTRACE_WAIT_ENTRIES', 'SLEEP_BPOOL_FLUSH', 'SQLTRACE_LOCK',
	'DIRTY_PAGE_POLL', 'HADR_FILESTREAM_IOMGR_IOCOMPLETION', 'SP_SERVER_DIAGNOSTICS_SLEEP') 
		AND wait_type NOT LIKE N'SLEEP_%'
	GROUP BY wait_type, wait_time_ms, signal_wait_time_ms)
SELECT 'Historical_Waits' AS [Information], W1.wait_type, 
	CAST(W1.wait_time_s AS DECIMAL(12, 2)) AS wait_time_s,
	CAST(W1.signal_wait_time_s AS DECIMAL(12, 2)) AS signal_wait_time_s,
	CAST(W1.resource_wait_time_s AS DECIMAL(12, 2)) AS resource_wait_time_s,
	CAST(W1.pct AS DECIMAL(12, 2)) AS pct,
	CAST(SUM(W2.pct) AS DECIMAL(12, 2)) AS overall_running_pct,
	CAST(W1.signal_wait_pct AS DECIMAL(12, 2)) AS signal_wait_pct,
	CAST(W1.resource_wait_pct AS DECIMAL(12, 2)) AS resource_wait_pct,
	CASE WHEN W1.wait_type LIKE N'LCK_%' OR W1.wait_type = N'LOCK' THEN N'Lock'
		-- LATCH = indicates contention for access to some non-page structures. ACCESS_METHODS_DATASET_PARENT, ACCESS_METHODS_SCAN_RANGE_GENERATOR or NESTING_TRANSACTION_FULL latches indicate parallelism issues;
		WHEN W1.wait_type LIKE N'LATCH_%' THEN N'Latch'
		-- PAGELATCH = indicates contention for access to in-memory copies of pages, like PFS, SGAM and GAM;
		WHEN W1.wait_type LIKE N'PAGELATCH_%' THEN N'Buffer Latch'
		-- PAGEIOLATCH = indicates IO problems, or BP pressure.
		WHEN W1.wait_type LIKE N'PAGEIOLATCH_%' THEN N'Buffer IO'
		WHEN W1.wait_type LIKE N'HADR_SYNC_COMMIT' THEN N'AlwaysOn - Secondary Synch' 
		WHEN W1.wait_type LIKE N'HADR_%' THEN N'AlwaysOn'
		WHEN W1.wait_type LIKE N'FFT_%' THEN N'FileTable'
		-- PREEMPTIVE_OS_WRITEFILEGATHERER (2008+) = usually autogrow scenarios, usually together with WRITELOG;
		WHEN W1.wait_type LIKE N'PREEMPTIVE_%' THEN N'External APIs or XPs' -- Used to indicate a worker is running code that is not under the SQLOS Scheduling;
		-- IO_COMPLETION = usually TempDB spilling; 
		-- ASYNC_IO_COMPLETION = usually when not using IFI, or waiting on backups.
		-- DISKIO_SUSPEND = High wait times here indicate the SNAPSHOT BACKUP may be taking longer than expected. Typically the delay is within the VDI application perform the snapshot backup;
		WHEN W1.wait_type IN (N'IO_COMPLETION', N'ASYNC_IO_COMPLETION', /*N'HADR_FILESTREAM_IOMGR_IOCOMPLETION',*/ N'DISKIO_SUSPEND') THEN N'Other IO'
		-- BACKUPIO = check for slow backup media slow, like Tapes or Disks;
		-- BACKUPBUFFER = usually when backing up to Tape;
		WHEN W1.wait_type IN(N'BACKUPIO', N'BACKUPBUFFER') THEN 'Backup IO'
		-- THREADPOOL = Look for high blocking or contention problems with workers. This will not show up in sys.dm_exec_requests;
		WHEN W1.wait_type = N'THREADPOOL' THEN 'CPU - Unavailable Worker Threads'
		-- SOS_SCHEDULER_YIELD = Might indicate CPU pressure if very high overall percentage. Check yielding conditions in http://technet.microsoft.com/en-us/library/cc917684.aspx
		WHEN W1.wait_type = N'SOS_SCHEDULER_YIELD' THEN N'CPU - Scheduler Yielding'
		-- Check sys.dm_os_waiting_tasks for Exchange wait types in http://technet.microsoft.com/en-us/library/ms188743.aspx;
			-- Wait Resource e_waitPipeNewRow in CXPACKET waits Producer waiting on consumer for a packet to fill;
			-- Wait Resource e_waitPipeGetRow in CXPACKET waits Consumer waiting on producer to fill a packet;
		-- CXPACKET = if OLTP, check for parallelism issues if above 20 pct. If combined with a high number of PAGEIOLATCH_XX waits, it could be large parallel table scans going on because of incorrect non-clustered indexes, or out-of-date statistics causing a bad query plan;
			WHEN W1.wait_type IN (N'CXPACKET', N'EXCHANGE') THEN N'CPU - Parallelism'
		-- WRITELOG = log management system waiting for a log flush to disk. Examine the IO latency for the log file
		WHEN W1.wait_type IN (N'LOGMGR', N'LOGBUFFER', N'LOGMGR_RESERVE_APPEND', N'LOGMGR_FLUSH', N'WRITELOG') THEN N'Logging'
		WHEN W1.wait_type IN (N'NET_WAITFOR_PACKET',N'NETWORK_IO') THEN N'Network IO'
		WHEN W1.wait_type = N'ASYNC_NETWORK_IO' THEN N'Client Network IO'
		-- RESOURCE_SEMAPHORE_SMALL_QUERY or RESOURCE_SEMAPHORE = queries are waiting for execution memory. Look for plans with excessive hashing or sorts.
		-- CMEMTHREAD =  indicates that the rate of insertion of entries into the plan cache is very high and there is contention; 
		-- http://blogs.msdn.com/b/psssql/archive/2012/12/20/how-it-works-cmemthread-and-debugging-them.aspx
		-- SOS_RESERVEDMEMBLOCKLIST = look for procedures with a large number of parameters, or queries with a long list of expression values specified in an IN clause, which would require multi-page allocations
		WHEN W1.wait_type IN (N'RESOURCE_SEMAPHORE_SMALL_QUERY',N'UTIL_PAGE_ALLOC',N'SOS_VIRTUALMEMORY_LOW',N'RESOURCE_SEMAPHORE', N'CMEMTHREAD', N'SOS_RESERVEDMEMBLOCKLIST') THEN N'Memory' 
		WHEN W1.wait_type LIKE N'CLR_%' OR W1.wait_type LIKE N'SQLCLR%' THEN N'CLR'
		-- DBMIRROR_DBM_MUTEX = indicates contention for the send buffer that database mirroring shares between all the mirroring sessions. 
		WHEN W1.wait_type LIKE N'DBMIRROR%' OR W1.wait_type = N'MIRROR_SEND_MESSAGE' THEN N'Mirroring'
		-- RESOURCE_SEMAPHORE_QUERY_COMPILE = usually high compilation or recompilation scenario (higher ratio of prepared plans vs. compiled plans). On x64 usually memory hungry queries and compiles. On x86 perhaps short on VAS.
		WHEN W1.wait_type LIKE N'RESOURCE_SEMAPHORE_%' OR W1.wait_type LIKE N'RESOURCE_SEMAPHORE_QUERY_COMPILE' THEN N'Compilation' 
		WHEN W1.wait_type LIKE N'XACT%' OR W1.wait_type LIKE N'DTC_%' OR W1.wait_type LIKE N'TRAN_MARKLATCH_%' OR W1.wait_type LIKE N'MSQL_XACT_%' OR W1.wait_type = N'TRANSACTION_MUTEX' THEN N'Transaction'
	--	WHEN W1.wait_type LIKE N'SLEEP_%' OR W1.wait_type IN(N'LAZYWRITER_SLEEP', N'SQLTRACE_BUFFER_FLUSH', N'WAITFOR', N'WAIT_FOR_RESULTS', N'SQLTRACE_INCREMENTAL_FLUSH_SLEEP', N'SLEEP_TASK', N'SLEEP_SYSTEMTASK') THEN N'Sleep'
		WHEN W1.wait_type LIKE N'FT_%' THEN N'Full Text'
	ELSE N'Other' END AS 'wait_category'
FROM Waits AS W1 INNER JOIN Waits AS W2 ON W2.rn <= W1.rn
GROUP BY W1.rn, W1.wait_type, W1.wait_time_s, W1.pct, W1.signal_wait_time_s, W1.resource_wait_time_s, W1.signal_wait_pct, W1.resource_wait_pct
HAVING W1.wait_time_s >= 0.01 AND (SUM(W2.pct)-W1.pct) < 100  -- percentage threshold
ORDER BY W1.rn;

;WITH cteLatches1 (latch_class,wait_time_ms,waiting_requests_count) AS (SELECT latch_class,wait_time_ms,waiting_requests_count FROM #tblLatches WHERE [retrieval_time] = @minctr),
	cteLatches2 (latch_class,wait_time_ms,waiting_requests_count) AS (SELECT latch_class,wait_time_ms,waiting_requests_count FROM #tblLatches WHERE [retrieval_time] = @maxctr)
INSERT INTO #tblFinalLatches
SELECT DISTINCT t1.latch_class,
		(t2.wait_time_ms-t1.wait_time_ms) / 1000.0 AS wait_time_s,
		(t2.waiting_requests_count-t1.waiting_requests_count) AS waiting_requests_count,
		100.0 * (t2.wait_time_ms-t1.wait_time_ms) / SUM(t2.wait_time_ms-t1.wait_time_ms) OVER() AS pct,
		ROW_NUMBER() OVER(ORDER BY t1.wait_time_ms DESC) AS rn
FROM cteLatches1 t1 INNER JOIN cteLatches2 t2 ON t1.latch_class = t2.latch_class
GROUP BY t1.latch_class, t1.wait_time_ms, t2.wait_time_ms, t1.waiting_requests_count, t2.waiting_requests_count
HAVING (t2.wait_time_ms-t1.wait_time_ms) > 0
ORDER BY wait_time_s DESC;

SELECT 'Latches_Last_90s' AS [Information], W1.latch_class, 
	CAST(W1.wait_time_s AS DECIMAL(14, 2)) AS wait_time_s,
	W1.waiting_requests_count,
	CAST (W1.pct AS DECIMAL(14, 2)) AS pct,
	CAST(SUM(W1.pct) AS DECIMAL(12, 2)) AS overall_running_pct,
	CAST ((W1.wait_time_s / W1.waiting_requests_count) AS DECIMAL (14, 4)) AS avg_wait_s,
CASE WHEN W1.latch_class LIKE N'ACCESS_METHODS_HOBT_COUNT' 
		OR W1.latch_class LIKE N'ACCESS_METHODS_HOBT_VIRTUAL_ROOT' THEN N'[HoBT - Metadata]'
	WHEN W1.latch_class LIKE N'ACCESS_METHODS_DATASET_PARENT' 
		OR W1.latch_class LIKE N'ACCESS_METHODS_SCAN_RANGE_GENERATOR' 
		OR W1.latch_class LIKE N'NESTING_TRANSACTION_FULL' THEN N'[Parallelism]'
	WHEN W1.latch_class LIKE N'LOG_MANAGER' THEN N'[IO - Log]'
	WHEN W1.latch_class LIKE N'TRACE_CONTROLLER' THEN N'[Trace]'
	WHEN W1.latch_class LIKE N'DBCC_MULTIOBJECT_SCANNER' THEN N'[Parallelism - DBCC CHECK_]'
	WHEN W1.latch_class LIKE N'FGCB_ADD_REMOVE' THEN N'[IO Operations]'
	WHEN W1.latch_class LIKE N'DATABASE_MIRRORING_CONNECTION' THEN N'[Mirroring - Busy]'
	WHEN W1.latch_class LIKE N'BUFFER' THEN N'[Buffer Pool - PAGELATCH or PAGEIOLATCH]'
	ELSE N'[Other]' END AS 'latch_category'
FROM #tblFinalLatches AS W1 INNER JOIN #tblFinalLatches AS W2 ON W2.rn <= W1.rn
GROUP BY W1.rn, W1.latch_class, W1.wait_time_s, W1.waiting_requests_count, W1.pct
HAVING SUM (W2.pct) - W1.pct < 100; -- percentage threshold
	
;WITH Latches AS
		(SELECT latch_class,
			wait_time_ms / 1000.0 AS wait_time_s,
			waiting_requests_count,
			100.0 * wait_time_ms / SUM(wait_time_ms) OVER() AS pct,
			ROW_NUMBER() OVER(ORDER BY wait_time_ms DESC) AS rn
		FROM sys.dm_os_latch_stats
		WHERE /*latch_class NOT IN ('BUFFER')
			AND*/ wait_time_ms > 0
	)
	SELECT 'Historical_Latches' AS [Information], W1.latch_class, 
	CAST(W1.wait_time_s AS DECIMAL(14, 2)) AS wait_time_s,
	W1.waiting_requests_count,
	CAST(W1.pct AS DECIMAL(14, 2)) AS pct,
	CAST(SUM(W1.pct) AS DECIMAL(12, 2)) AS overall_running_pct,
	CAST((W1.wait_time_s / W1.waiting_requests_count) AS DECIMAL (14, 4)) AS avg_wait_s,
		-- ACCESS_METHODS_HOBT_VIRTUAL_ROOT = This latch is used to access the metadata for an index that contains the page ID of the index's root page. Contention on this latch can occur when a B-tree root page split occurs (requiring the latch in EX mode) and threads wanting to navigate down the B-tree (requiring the latch in SH mode) have to wait. This could be from very fast population of a small index using many concurrent connections, with or without page splits from random key values causing cascading page splits (from leaf to root).
		-- ACCESS_METHODS_HOBT_COUNT = This latch is used to flush out page and row count deltas for a HoBt (Heap-or-B-tree) to the Storage Engine metadata tables. Contention would indicate *lots* of small, concurrent DML operations on a single table. 
	CASE WHEN W1.latch_class LIKE N'ACCESS_METHODS_HOBT_COUNT' 
		OR W1.latch_class LIKE N'ACCESS_METHODS_HOBT_VIRTUAL_ROOT' THEN N'[HoBT - Metadata]'
		-- ACCESS_METHODS_DATASET_PARENT and ACCESS_METHODS_SCAN_RANGE_GENERATOR = These two latches are used during parallel scans to give each thread a range of page IDs to scan. The LATCH_XX waits for these latches will typically appear with CXPACKET waits and PAGEIOLATCH_XX waits (if the data being scanned is not memory-resident). Use normal parallelism troubleshooting methods to investigate further (e.g. is the parallelism warranted? maybe increase 'cost threshold for parallelism', lower MAXDOP, use a MAXDOP hint, use Resource Governor to limit DOP using a workload group with a MAX_DOP limit. Did a plan change from index seeks to parallel table scans because a tipping point was reached or a plan recompiled with an atypical SP parameter or poor statistics? Do NOT knee-jerk and set server MAXDOP to 1 – that's some of the worst advice I see on the Internet.);
		-- NESTING_TRANSACTION_FULL  = This latch, along with NESTING_TRANSACTION_READONLY, is used to control access to transaction description structures (called an XDES) for parallel nested transactions. The _FULL is for a transaction that's 'active', i.e. it's changed the database (usually for an index build/rebuild), and that makes the _READONLY description obvious. A query that involves a parallel operator must start a sub-transaction for each parallel thread that is used – these transactions are sub-transactions of the parallel nested transaction. For contention on these, I'd investigate unwanted parallelism but I don't have a definite "it's usually this problem". Also check out the comments for some info about these also sometimes being a problem when RCSI is used.
		WHEN W1.latch_class LIKE N'ACCESS_METHODS_DATASET_PARENT' 
			OR W1.latch_class LIKE N'ACCESS_METHODS_SCAN_RANGE_GENERATOR' 
			OR W1.latch_class LIKE N'NESTING_TRANSACTION_FULL' THEN N'[Parallelism]'
		-- LOG_MANAGER = you see this latch it is almost certainly because a transaction log is growing because it could not clear/truncate for some reason. Find the database where the log is growing and then figure out what's preventing log clearing using sys.databases.
		WHEN W1.latch_class LIKE N'LOG_MANAGER' THEN N'[IO - Log]'
		WHEN W1.latch_class LIKE N'TRACE_CONTROLLER' THEN N'[Trace]'
		-- DBCC_MULTIOBJECT_SCANNER  = This latch appears on Enterprise Edition when DBCC CHECK_ commands are allowed to run in parallel. It is used by threads to request the next data file page to process. Late last year this was identified as a major contention point inside DBCC CHECK* and there was work done to reduce the contention and make DBCC CHECK* run faster.
		-- http://blogs.msdn.com/b/psssql/archive/2012/02/23/a-faster-checkdb-part-ii.aspx
		WHEN W1.latch_class LIKE N'DBCC_MULTIOBJECT_SCANNER ' THEN N'[Parallelism - DBCC CHECK_]'
		-- FGCB_ADD_REMOVE = FGCB stands for File Group Control Block. This latch is required whenever a file is added or dropped from the filegroup, whenever a file is grown (manually or automatically), when recalculating proportional-fill weightings, and when cycling through the files in the filegroup as part of round-robin allocation. If you're seeing this, the most common cause is that there's a lot of file auto-growth happening. It could also be from a filegroup with lots of file (e.g. the primary filegroup in tempdb) where there are thousands of concurrent connections doing allocations. The proportional-fill weightings are recalculated every 8192 allocations, so there's the possibility of a slowdown with frequent recalculations over many files.
		WHEN W1.latch_class LIKE N'FGCB_ADD_REMOVE' THEN N'[IO Operations]'
		WHEN W1.latch_class LIKE N'DATABASE_MIRRORING_CONNECTION ' THEN N'[Mirroring - Busy]'
		WHEN W1.latch_class LIKE N'BUFFER' THEN N'[Buffer Pool - PAGELATCH or PAGEIOLATCH]'
		ELSE N'Other' END AS 'latch_category'
FROM Latches AS W1
INNER JOIN Latches AS W2
	ON W2.rn <= W1.rn
GROUP BY W1.rn, W1.latch_class, W1.wait_time_s, W1.waiting_requests_count, W1.pct
HAVING SUM (W2.pct) - W1.pct < 100; -- percentage threshold
	
	;WITH Latches AS
		(SELECT latch_class,
			wait_time_ms / 1000.0 AS wait_time_s,
			waiting_requests_count,
			100.0 * wait_time_ms / SUM(wait_time_ms) OVER() AS pct,
			ROW_NUMBER() OVER(ORDER BY wait_time_ms DESC) AS rn
		FROM sys.dm_os_latch_stats (NOLOCK)
		WHERE latch_class NOT IN ('BUFFER')
			AND wait_time_ms > 0
	)
	SELECT 'Historical_Latches_wo_BUFFER' AS [Information], W1.latch_class, 
	CAST(W1.wait_time_s AS DECIMAL(14, 2)) AS wait_time_s,
	W1.waiting_requests_count,
	CAST(W1.pct AS DECIMAL(14, 2)) AS pct,
	CAST(SUM(W1.pct) AS DECIMAL(12, 2)) AS overall_running_pct,
	CAST((W1.wait_time_s / W1.waiting_requests_count) AS DECIMAL (14, 4)) AS avg_wait_s,
		-- ACCESS_METHODS_HOBT_VIRTUAL_ROOT = This latch is used to access the metadata for an index that contains the page ID of the index's root page. Contention on this latch can occur when a B-tree root page split occurs (requiring the latch in EX mode) and threads wanting to navigate down the B-tree (requiring the latch in SH mode) have to wait. This could be from very fast population of a small index using many concurrent connections, with or without page splits from random key values causing cascading page splits (from leaf to root).
		-- ACCESS_METHODS_HOBT_COUNT = This latch is used to flush out page and row count deltas for a HoBt (Heap-or-B-tree) to the Storage Engine metadata tables. Contention would indicate *lots* of small, concurrent DML operations on a single table. 
	CASE WHEN W1.latch_class LIKE N'ACCESS_METHODS_HOBT_COUNT' 
		OR W1.latch_class LIKE N'ACCESS_METHODS_HOBT_VIRTUAL_ROOT' THEN N'[HoBT - Metadata]'
		-- ACCESS_METHODS_DATASET_PARENT and ACCESS_METHODS_SCAN_RANGE_GENERATOR = These two latches are used during parallel scans to give each thread a range of page IDs to scan. The LATCH_XX waits for these latches will typically appear with CXPACKET waits and PAGEIOLATCH_XX waits (if the data being scanned is not memory-resident). Use normal parallelism troubleshooting methods to investigate further (e.g. is the parallelism warranted? maybe increase 'cost threshold for parallelism', lower MAXDOP, use a MAXDOP hint, use Resource Governor to limit DOP using a workload group with a MAX_DOP limit. Did a plan change from index seeks to parallel table scans because a tipping point was reached or a plan recompiled with an atypical SP parameter or poor statistics? Do NOT knee-jerk and set server MAXDOP to 1 – that's some of the worst advice I see on the Internet.);
		-- NESTING_TRANSACTION_FULL  = This latch, along with NESTING_TRANSACTION_READONLY, is used to control access to transaction description structures (called an XDES) for parallel nested transactions. The _FULL is for a transaction that's 'active', i.e. it's changed the database (usually for an index build/rebuild), and that makes the _READONLY description obvious. A query that involves a parallel operator must start a sub-transaction for each parallel thread that is used – these transactions are sub-transactions of the parallel nested transaction. For contention on these, I'd investigate unwanted parallelism but I don't have a definite "it's usually this problem". Also check out the comments for some info about these also sometimes being a problem when RCSI is used.
		WHEN W1.latch_class LIKE N'ACCESS_METHODS_DATASET_PARENT' 
			OR W1.latch_class LIKE N'ACCESS_METHODS_SCAN_RANGE_GENERATOR' 
			OR W1.latch_class LIKE N'NESTING_TRANSACTION_FULL' THEN N'[Parallelism]'
		-- LOG_MANAGER = you see this latch it is almost certainly because a transaction log is growing because it could not clear/truncate for some reason. Find the database where the log is growing and then figure out what's preventing log clearing using sys.databases.
		WHEN W1.latch_class LIKE N'LOG_MANAGER' THEN N'[IO - Log]'
		WHEN W1.latch_class LIKE N'TRACE_CONTROLLER' THEN N'[Trace]'
		-- DBCC_MULTIOBJECT_SCANNER  = This latch appears on Enterprise Edition when DBCC CHECK_ commands are allowed to run in parallel. It is used by threads to request the next data file page to process. Late last year this was identified as a major contention point inside DBCC CHECK* and there was work done to reduce the contention and make DBCC CHECK* run faster.
		-- http://blogs.msdn.com/b/psssql/archive/2012/02/23/a-faster-checkdb-part-ii.aspx
		WHEN W1.latch_class LIKE N'DBCC_MULTIOBJECT_SCANNER ' THEN N'[Parallelism - DBCC CHECK_]'
		-- FGCB_ADD_REMOVE = FGCB stands for File Group Control Block. This latch is required whenever a file is added or dropped from the filegroup, whenever a file is grown (manually or automatically), when recalculating proportional-fill weightings, and when cycling through the files in the filegroup as part of round-robin allocation. If you're seeing this, the most common cause is that there's a lot of file auto-growth happening. It could also be from a filegroup with lots of file (e.g. the primary filegroup in tempdb) where there are thousands of concurrent connections doing allocations. The proportional-fill weightings are recalculated every 8192 allocations, so there's the possibility of a slowdown with frequent recalculations over many files.
		WHEN W1.latch_class LIKE N'FGCB_ADD_REMOVE' THEN N'[IO Operations]'
		WHEN W1.latch_class LIKE N'DATABASE_MIRRORING_CONNECTION ' THEN N'[Mirroring - Busy]'
		WHEN W1.latch_class LIKE N'BUFFER' THEN N'[Buffer Pool - PAGELATCH or PAGEIOLATCH]'
		ELSE N'Other' END AS 'latch_category'
FROM Latches AS W1
INNER JOIN Latches AS W2
	ON W2.rn <= W1.rn
GROUP BY W1.rn, W1.latch_class, W1.wait_time_s, W1.waiting_requests_count, W1.pct
HAVING SUM (W2.pct) - W1.pct < 100; -- percentage threshold

--------------------------------------------------------------------------------------------------------------------------------
-- Worker thread exhaustion subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Worker thread exhaustion subsection', 10, 1) WITH NOWAIT
	
DECLARE @avgtskcnt int, @workqcnt int
SELECT @avgtskcnt = SUM(runnable_tasks_count)/COUNT(scheduler_id), @workqcnt = SUM(work_queue_count) FROM sys.dm_os_schedulers
WHERE parent_node_id < 64 AND scheduler_id < 255

IF @avgtskcnt <= 2 AND @workqcnt > 1
BEGIN
	SELECT 'Worker_thread_exhaustion' AS [Check], '[WARNING: Possible worker thread exhaustion (schedulers work queue count is ' + CONVERT(NVARCHAR(10), @workqcnt) + '). Because overall runnable tasks count is ' + CONVERT(NVARCHAR(10), @avgtskcnt) + ' (<= 2), indicating the server might not be CPU bound, there might be room to increase max_worker_threads]' AS [Deviation], '[Configured workers = ' + CONVERT(VARCHAR(10),@mwthreads_count) + ']' AS [Comment]
END
ELSE IF @avgtskcnt > 2 AND @workqcnt > 1
BEGIN
	SELECT 'Worker_thread_exhaustion' AS [Check], '[WARNING: Possible worker thread exhaustion (schedulers work queue count is ' + CONVERT(NVARCHAR(10), @workqcnt) + '). Overall runnable tasks count is ' + CONVERT(NVARCHAR(10), @avgtskcnt) + ' (> 2), also indicating the server might be CPU bound]' AS [Deviation], '[Configured workers = ' + CONVERT(VARCHAR(10),@mwthreads_count) + ']' AS [Comment]
END
ELSE
BEGIN
	SELECT 'Worker_thread_exhaustion' AS [Check], '[OK]' AS [Deviation], '' AS [Comment]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Plan use ratio subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Plan use ratio subsection', 10, 1) WITH NOWAIT

IF (SELECT SUM(CAST(size_in_bytes AS bigint))/1024/1024 AS Size_MB
	FROM sys.dm_exec_cached_plans (NOLOCK)
	WHERE cacheobjtype LIKE '%Plan%' AND usecounts = 1) 
	>= 
	(SELECT SUM(CAST(size_in_bytes AS bigint))/1024/1024 AS Size_MB
	FROM sys.dm_exec_cached_plans (NOLOCK)
	WHERE cacheobjtype LIKE '%Plan%' AND usecounts > 1)
BEGIN
	SELECT 'Plan_use_ratio' AS [Check], '[WARNING: Amount of single use plans in cache is high]' AS [Deviation], CASE WHEN @sqlmajorver > 9 AND @adhoc = 0 THEN '[Consider enabling the Optimize for ad hoc workloads setting on heavy OLTP ad-hoc worloads to conserve resources]' ELSE '' END AS [Comment]
END
ELSE
BEGIN
	SELECT 'Plan_use_ratio' AS [Check], '[OK]' AS [Deviation], '' AS [Comment]
END;

--High number of cached plans with usecounts = 1.
SELECT 'Plan_use_ratio' AS [Information], objtype, cacheobjtype, AVG(usecounts) AS Avg_UseCount, SUM(refcounts) AS Ref_Objects, SUM(CAST(size_in_bytes AS bigint))/1024/1024 AS Size_MB
FROM sys.dm_exec_cached_plans (NOLOCK)
WHERE cacheobjtype LIKE '%Plan%' AND usecounts = 1
GROUP BY objtype, cacheobjtype
UNION ALL
--High number of cached plans with usecounts > 1.
SELECT 'Plan_use_ratio' AS [Information], objtype, cacheobjtype, AVG(usecounts) AS Avg_UseCount_perPlan, SUM(refcounts) AS AllRefObjects, SUM(CAST(size_in_bytes AS bigint))/1024/1024 AS Size_MB
FROM sys.dm_exec_cached_plans (NOLOCK)
WHERE cacheobjtype LIKE '%Plan%' AND usecounts > 1
GROUP BY objtype, cacheobjtype
ORDER BY objtype, cacheobjtype;

--------------------------------------------------------------------------------------------------------------------------------
-- Hints usage subsection
-- Refer to "Hints" BOL entry for more information (http://msdn.microsoft.com/en-us/library/ms187713.aspx)
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Hints usage subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT([counter]) FROM sys.dm_exec_query_optimizer_info WHERE ([counter] = 'order hint' OR [counter] = 'join hint') AND occurrence > 1) > 0
BEGIN
	SELECT 'Hints_usage' AS [Check], '[WARNING: Hints are being used. These can hinder the QO ability to optimize queries]' AS [Deviation]
	SELECT 'Hints_usage' AS [Information], CASE WHEN [counter] = 'order hint' THEN '[FORCE ORDER Hint]' WHEN [counter] = 'join hint' THEN '[JOIN Hint]' END AS [counter], occurrence, value
	FROM sys.dm_exec_query_optimizer_info (NOLOCK)
	WHERE ([counter] = 'order hint' OR [counter] = 'join hint') AND occurrence > 1
END
ELSE
BEGIN
	SELECT 'Hints_usage' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Cached Query Plans issues subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Cached Query Plans issues subsection', 10, 1) WITH NOWAIT
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmp_dm_exec_query_stats%') 
DROP TABLE #tmp_dm_exec_query_stats;

IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmp_dm_exec_query_stats%') 
CREATE TABLE #tmp_dm_exec_query_stats ([plan_id] [int] NOT NULL IDENTITY(1, 1),
	[sql_handle] [varbinary](64) NOT NULL,
	[statement_start_offset] [int] NOT NULL,
	[statement_end_offset] [int] NOT NULL,
	[plan_generation_num] [bigint] NOT NULL,
	[plan_handle] [varbinary](64) NOT NULL,
	[creation_time] [datetime] NOT NULL,
	[last_execution_time] [datetime] NOT NULL,
	[execution_count] [bigint] NOT NULL,
	[total_worker_time] [bigint] NOT NULL,
	[last_worker_time] [bigint] NOT NULL,
	[min_worker_time] [bigint] NOT NULL,
	[max_worker_time] [bigint] NOT NULL,
	[total_physical_reads] [bigint] NOT NULL,
	[last_physical_reads] [bigint] NOT NULL,
	[min_physical_reads] [bigint] NOT NULL,
	[max_physical_reads] [bigint] NOT NULL,
	[total_logical_writes] [bigint] NOT NULL,
	[last_logical_writes] [bigint] NOT NULL,
	[min_logical_writes] [bigint] NOT NULL,
	[max_logical_writes] [bigint] NOT NULL,
	[total_logical_reads] [bigint] NOT NULL,
	[last_logical_reads] [bigint] NOT NULL,
	[min_logical_reads] [bigint] NOT NULL,
	[max_logical_reads] [bigint] NOT NULL,
	[total_clr_time] [bigint] NOT NULL,
	[last_clr_time] [bigint] NOT NULL,
	[min_clr_time] [bigint] NOT NULL,
	[max_clr_time] [bigint] NOT NULL,
	[total_elapsed_time] [bigint] NOT NULL,
	[last_elapsed_time] [bigint] NOT NULL,
	[min_elapsed_time] [bigint] NOT NULL,
	[max_elapsed_time] [bigint] NOT NULL,
	--2008 only
	[query_hash] [binary](8) NULL,
	[query_plan_hash] [binary](8) NULL,
	--2008R2 only
	[total_rows] bigint NULL,
	[last_rows] bigint NULL,
	[min_rows] bigint NULL,
	[max_rows] bigint NULL)

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dm_exec_query_stats%') 
DROP TABLE #dm_exec_query_stats;

IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dm_exec_query_stats%') 
CREATE TABLE #dm_exec_query_stats ([plan_id] [int] NOT NULL IDENTITY(1, 1),
	[sql_handle] [varbinary](64) NOT NULL,
	[statement_start_offset] [int] NOT NULL,
	[statement_end_offset] [int] NOT NULL,
	[plan_generation_num] [bigint] NOT NULL,
	[plan_handle] [varbinary](64) NOT NULL,
	[creation_time] [datetime] NOT NULL,
	[last_execution_time] [datetime] NOT NULL,
	[execution_count] [bigint] NOT NULL,
	[total_worker_time] [bigint] NOT NULL,
	[last_worker_time] [bigint] NOT NULL,
	[min_worker_time] [bigint] NOT NULL,
	[max_worker_time] [bigint] NOT NULL,
	[total_physical_reads] [bigint] NOT NULL,
	[last_physical_reads] [bigint] NOT NULL,
	[min_physical_reads] [bigint] NOT NULL,
	[max_physical_reads] [bigint] NOT NULL,
	[total_logical_writes] [bigint] NOT NULL,
	[last_logical_writes] [bigint] NOT NULL,
	[min_logical_writes] [bigint] NOT NULL,
	[max_logical_writes] [bigint] NOT NULL,
	[total_logical_reads] [bigint] NOT NULL,
	[last_logical_reads] [bigint] NOT NULL,
	[min_logical_reads] [bigint] NOT NULL,
	[max_logical_reads] [bigint] NOT NULL,
	[total_clr_time] [bigint] NOT NULL,
	[last_clr_time] [bigint] NOT NULL,
	[min_clr_time] [bigint] NOT NULL,
	[max_clr_time] [bigint] NOT NULL,
	[total_elapsed_time] [bigint] NOT NULL,
	[last_elapsed_time] [bigint] NOT NULL,
	[min_elapsed_time] [bigint] NOT NULL,
	[max_elapsed_time] [bigint] NOT NULL,
	--2008 only
	[query_hash] [binary](8) NULL,
	[query_plan_hash] [binary](8) NULL,
	--2008R2 only
	[total_rows] bigint NULL,
	[last_rows] bigint NULL,
	[min_rows] bigint NULL,
	[max_rows] bigint NULL,
	--end
	[query_plan] [xml] NULL,
	[text] [nvarchar](MAX) COLLATE database_default NULL,
	[text_filtered] [nvarchar](MAX) COLLATE database_default NULL)

IF @sqlmajorver = 9
BEGIN
	--CPU 
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
	--FROM sys.dm_exec_query_stats qs (NOLOCK) 
	--ORDER BY qs.total_worker_time DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.total_worker_time DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.total_worker_time DESC');
	--IO
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.total_logical_reads DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.total_logical_reads DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.total_logical_reads DESC');
	--Recompiles
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.plan_generation_num DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.plan_generation_num DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.plan_generation_num DESC');
END
ELSE IF @sqlmajorver = 10 AND (@sqlminorver = 0 OR (@sqlminorver = 50 AND @sqlbuild < 2500))
BEGIN
	--CPU 
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.total_worker_time DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.total_worker_time DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.total_worker_time DESC');
	--IO
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.total_logical_reads DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.total_logical_reads DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.total_logical_reads DESC');
	--Recompiles
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.plan_generation_num DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.plan_generation_num DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.plan_generation_num DESC');
END
ELSE IF (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500) OR @sqlmajorver > 10
BEGIN
	--CPU 
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.total_worker_time DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.total_worker_time DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.total_worker_time DESC');
	--IO
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.total_logical_reads DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.total_logical_reads DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.total_logical_reads DESC');
	--Recompiles
	INSERT INTO #tmp_dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows])
	--EXEC ('SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
	--FROM sys.dm_exec_query_stats qs (NOLOCK)
	--ORDER BY qs.plan_generation_num DESC');
	EXEC (';WITH XMLNAMESPACES (DEFAULT ''http://schemas.microsoft.com/sqlserver/2004/07/showplan''), 
TopSearch AS (SELECT DISTINCT TOP 25 [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
FROM sys.dm_exec_query_stats qs (NOLOCK)
ORDER BY qs.plan_generation_num DESC),
TopFineSearch AS (SELECT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows],ix.query(''.'') AS StmtSimple
FROM TopSearch ts
OUTER APPLY sys.dm_exec_query_plan(ts.plan_handle) qp
CROSS APPLY qp.query_plan.nodes(''//StmtSimple'') AS p(ix))
SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
FROM TopFineSearch tfs
CROSS APPLY StmtSimple.nodes(''//Object'') AS o(obj)
WHERE obj.value(''@Database'',''sysname'') NOT IN (''[master]'',''[mssqlsystemresource]'')
ORDER BY tfs.plan_generation_num DESC');
END;

-- Remove duplicates before inserting XML
IF @sqlmajorver = 9
BEGIN
	INSERT INTO #dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time])
	SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time]
	FROM #tmp_dm_exec_query_stats;
END
ELSE IF @sqlmajorver = 10 AND (@sqlminorver = 0 OR (@sqlminorver = 50 AND @sqlbuild < 2500))
BEGIN
	INSERT INTO #dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash])
	SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash]
	FROM #tmp_dm_exec_query_stats;
END
ELSE IF (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 2500) OR @sqlmajorver > 10
BEGIN
	INSERT INTO #dm_exec_query_stats ([sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows])
	SELECT DISTINCT [sql_handle],[statement_start_offset],[statement_end_offset],[plan_generation_num],[plan_handle],[creation_time],[last_execution_time],[execution_count],[total_worker_time],[last_worker_time],[min_worker_time],[max_worker_time],[total_physical_reads],[last_physical_reads],[min_physical_reads],[max_physical_reads],[total_logical_writes],[last_logical_writes],[min_logical_writes],[max_logical_writes],[total_logical_reads],[last_logical_reads],[min_logical_reads],[max_logical_reads],[total_clr_time],[last_clr_time],[min_clr_time],[max_clr_time],[total_elapsed_time],[last_elapsed_time],[min_elapsed_time],[max_elapsed_time],[query_hash],[query_plan_hash],[total_rows],[last_rows],[min_rows],[max_rows]
	FROM #tmp_dm_exec_query_stats;
END;

UPDATE #dm_exec_query_stats
SET query_plan = qp.query_plan, 
	[text] = st.[text],
	text_filtered = SUBSTRING(st.[text], 
		(CASE WHEN qs.statement_start_offset = 0 THEN 0 ELSE qs.statement_start_offset/2 END),
		(CASE WHEN qs.statement_end_offset = -1 THEN DATALENGTH(st.[text]) ELSE qs.statement_end_offset/2 END - (CASE WHEN qs.statement_start_offset = 0 THEN 0 ELSE qs.statement_start_offset/2 END)))
FROM #dm_exec_query_stats qs
	CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) AS st
	CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) AS qp
	 
-- Delete own queries
DELETE FROM #dm_exec_query_stats
WHERE CAST(query_plan AS NVARCHAR(MAX)) LIKE '%Query_Plan_Warnings%';

-- Aggregate results
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#qpwarnings%') 
DROP TABLE #qpwarnings;

IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#qpwarnings%') 
CREATE TABLE #qpwarnings ([Check] CHAR(19), [Deviation] VARCHAR(50), [Comment] VARCHAR(255), query_plan XML, [statement] XML)

-- Find issues
INSERT INTO #qpwarnings
SELECT 'Query_Plan_Warnings' AS [Check], 'Scalar_UDFs'AS [Deviation],
	('[WARNING: One of the top resource-intensive queries is using a scalar UDF that may inhibit parallelism]') AS [Comment],
	qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
FROM #dm_exec_query_stats qs
WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%UserDefinedFunction%'
UNION ALL
SELECT 'Query_Plan_Warnings' AS [Check], 'Implicit_Conversion_with_IX_Scan'AS [Deviation],
	('[WARNING: One of the top resource-intensive queries performing implicit conversions where an Index Scan is present]' ) AS Details ,
	qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
FROM #dm_exec_query_stats qs
WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%CONVERT_IMPLICIT%'
	AND CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%PhysicalOp="Index Scan"%'
UNION ALL
SELECT 'Query_Plan_Warnings' AS [Check], 'Missing_Index'AS [Deviation],
	('[WARNING: One of the top resource-intensive queries may be improved by adding an index]') AS [Comment],
	qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
FROM #dm_exec_query_stats qs
WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%MissingIndexGroup%'
UNION ALL
SELECT 'Query_Plan_Warnings' AS [Check], 'Cursor'AS [Deviation],
	('[WARNING: One of the top resource-intensive queries is using a cursor. Check if it can be rewritten as a WHILE cycle]') AS [Comment],
	qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
FROM #dm_exec_query_stats qs
WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<CursorType%'
UNION ALL
SELECT 'Query_Plan_Warnings' AS [Check], 'Missing_Join_Predicate'AS [Deviation],
	('[WARNING: One of the top resource-intensive queries is being executed without a JOIN predicate]') AS [Comment],
	qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
FROM #dm_exec_query_stats qs
WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<Warnings NoJoinPredicate="true"%'
UNION ALL
SELECT 'Query_Plan_Warnings' AS [Check], 'Columns_with_no_Statistics'AS [Deviation],
	('[WARNING: One of the top resource-intensive queries is has issued Missing Column Statistics events]') AS [Comment],
	qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
FROM #dm_exec_query_stats qs
WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<Warnings ColumnsWithNoStatistics%';

IF @sqlmajorver > 10
BEGIN
	INSERT INTO #qpwarnings
	SELECT 'Query_Plan_Warnings' AS [Check], 'Spill_to_TempDb'AS [Deviation],
		('[WARNING: One of the top resource-intensive queries performed HASH or SORT operation that have spilt to tempDB]') AS [Comment],
		qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
	FROM #dm_exec_query_stats qs
	WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<SpillToTempDb SpillLevel%'
	UNION ALL
	SELECT 'Query_Plan_Warnings' AS [Check], 'Implicit_Convert_affecting_Seek_Plan'AS [Deviation],
		('[WARNING: One of the top resource-intensive queries performed implicit conversions that can be afecting the choice of seek plans]') AS [Comment],
		qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
	FROM #dm_exec_query_stats qs
	WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<PlanAffectingConvert ConvertIssue="Seek Plan" Expression="CONVERT_IMPLICIT%'
	UNION ALL
	SELECT 'Query_Plan_Warnings' AS [Check], 'Explicit_Conversion_affecting_Cardinality'AS [Deviation],
		('[WARNING: One of the top resource-intensive queries performed conversions that can be afecting cardinality estimates]') AS [Comment],
		qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
	FROM #dm_exec_query_stats qs
	WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<PlanAffectingConvert ConvertIssue="Cardinality Estimate" Expression="CONVERT%'
	UNION ALL
	SELECT 'Query_Plan_Warnings' AS [Check], 'Implicit_Conversion_affecting_Cardinality'AS [Deviation],
		('[WARNING: One of the top resource-intensive queries performed implicit conversions that can be afecting cardinality estimates]') AS [Comment],
		qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
	FROM #dm_exec_query_stats qs
	WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<PlanAffectingConvert ConvertIssue="Cardinality Estimate" Expression="CONVERT_IMPLICIT%'
	UNION ALL
	SELECT 'Query_Plan_Warnings' AS [Check], 'Unmatched_Indexes'AS [Deviation],
		('[WARNING: One of the top resource-intensive queries issued an unmatched indexes warning, where an index could not be used due to parameterization]') AS [Comment],
		qs.query_plan, (SELECT qs.text_filtered FOR XML PATH(''), TYPE) AS [statement]
	FROM #dm_exec_query_stats qs
	WHERE CAST(qs.query_plan AS NVARCHAR(MAX)) LIKE '%<Warnings UnmatchedIndexes="true"%';
END;

IF (SELECT COUNT(*) FROM #qpwarnings) > 0
BEGIN
	SELECT 'Query_Plan_Warnings' AS [Check], '[WARNING: Top resource-intensive queries issued plan level warnings]' AS [Deviation]
END
ELSE
BEGIN
	SELECT 'Query_Plan_Warnings' AS [Check], '[OK]' AS [Deviation]
END;

IF (SELECT COUNT(*) FROM #qpwarnings) > 0
BEGIN
	SELECT [Check], [Deviation], [Comment], query_plan, [statement]
	FROM #qpwarnings;
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Deprecated features subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Deprecated features subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(instance_name) FROM sys.dm_os_performance_counters WHERE [object_name] = 'SQLServer:Deprecated Features' AND cntr_value > 0) > 0
BEGIN
	SELECT 'Deprecated_features' AS [Check], '[WARNING: Deprecated features are being used. These features are scheduled to be removed in a future release of SQL Server]' AS [Deviation]
	SELECT 'Deprecated_features' AS [Information], instance_name, cntr_value AS [Times_used_since_startup]
	FROM sys.dm_os_performance_counters (NOLOCK)
	WHERE [object_name] LIKE '%Deprecated Features%' AND cntr_value > 0
	ORDER BY instance_name;
END
ELSE
BEGIN
	SELECT 'Deprecated_features' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Statistics update subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Statistics update subsection', 10, 1) WITH NOWAIT

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs2%')
DROP TABLE #tmpdbs2;
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs2%')
CREATE TABLE #tmpdbs2 (id int IDENTITY(1,1), [dbid] int, [dbname] VARCHAR(1000), isdone bit);

INSERT INTO #tmpdbs2 ([dbid], [dbname], isdone)
SELECT database_id, name, 0 FROM master.sys.databases (NOLOCK) WHERE is_read_only = 0 AND [state] = 0 AND database_id > 4 AND is_distributor = 0;

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblStatsUpd%')
DROP TABLE #tblStatsUpd
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblStatsUpd%')
CREATE TABLE #tblStatsUpd ([DatabaseName] sysname, [databaseID] int, objectID int, schemaName VARCHAR(100), [tableName] VARCHAR(250), [rows] bigint, modification_counter bigint, [stats_id] int, [stat_name] VARCHAR(255))

WHILE (SELECT COUNT(id) FROM #tmpdbs2 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs2 WHERE isdone = 0
	IF (@sqlmajorver = 10 AND @sqlminorver = 50 AND @sqlbuild >= 4000) OR (@sqlmajorver = 11 AND @sqlbuild >= 3000) OR @sqlmajorver > 11
	BEGIN
		SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT DISTINCT ''' + @dbname + ''' AS [DatabaseName], ''' + CONVERT(VARCHAR(12),@dbid) + ''' AS [databaseID], mst.[object_id] AS objectID, t.name AS schemaName, OBJECT_NAME(mst.[object_id]) AS tableName, sp.[rows], sp.modification_counter, ss.[stats_id], ss.name AS [stat_name]
FROM sys.objects AS o
	INNER JOIN sys.tables AS mst ON mst.[object_id] = o.[object_id]
	INNER JOIN sys.schemas AS t ON t.[schema_id] = mst.[schema_id]
	INNER JOIN sys.stats AS ss ON ss.[object_id] = mst.[object_id]
	CROSS APPLY sys.dm_db_stats_properties(ss.[object_id], ss.[stats_id]) AS sp
WHERE sp.[rows] > 0
	AND	((sp.[rows] <= 500 AND sp.modification_counter >= 500)
		OR (sp.[rows] > 500 AND sp.modification_counter >= (500 + sp.[rows] * 0.20)))'
	END
	ELSE
	BEGIN
		SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT DISTINCT ''' + @dbname + ''' AS [DatabaseName], ''' + CONVERT(VARCHAR(12),@dbid) + ''' AS [databaseID], mst.[object_id] AS objectID, t.name AS schemaName, OBJECT_NAME(mst.[object_id]) AS tableName, SUM(p.[rows]) AS [rows], rowmodctr AS modification_counter, ss.stats_id, ss.name AS [stat_name]
FROM sys.sysindexes AS si
	INNER JOIN sys.objects AS o ON si.id = o.[object_id]
	INNER JOIN sys.tables AS mst ON mst.[object_id] = o.[object_id]
	INNER JOIN sys.schemas AS t ON t.[schema_id] = mst.[schema_id]
	INNER JOIN sys.stats AS ss ON ss.[object_id] = o.[object_id]
	INNER JOIN sys.partitions AS p ON p.[object_id] = ss.[object_id]
	LEFT JOIN sys.indexes i ON si.id = i.[object_id] AND si.indid = i.index_id
WHERE o.type <> ''S'' AND i.name IS NOT NULL
GROUP BY mst.[object_id], t.name, rowmodctr, ss.stats_id, ss.name
HAVING SUM(p.[rows]) > 0
	AND	((SUM(p.[rows]) <= 500 AND rowmodctr >= 500)
		OR (SUM(p.[rows]) > 500 AND rowmodctr >= (500 + SUM(p.[rows]) * 0.20)))'
	END
		
	BEGIN TRY
		INSERT INTO #tblStatsUpd
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Statistics update subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
		
	UPDATE #tmpdbs2
	SET isdone = 1
	WHERE dbid = @dbid
END;
	
CREATE INDEX IX_Stats ON #tblStatsUpd([databaseID]);

IF (SELECT COUNT(*) FROM #tblStatsUpd) > 0
BEGIN
	IF (SELECT COUNT(*) FROM master.sys.databases (NOLOCK) WHERE is_auto_update_stats_on = 0) > 0 AND (SELECT COUNT(*) FROM #tblStatsUpd AS su INNER JOIN master.sys.databases AS sd ON su.[databaseID] = sd.[database_id] WHERE sd.is_auto_update_stats_on = 0) > 0
	BEGIN
		SELECT 'Statistics_to_update' AS [Check], '[WARNING: Some databases have Auto_Update_Statistics DISABLED and statistics that might need to be updated]' AS [Deviation]
		SELECT 'Statistics_to_update' AS [Information], [DatabaseName] AS [Database_Name], schemaName, [tableName] AS [Table_Name], [rows], modification_counter, [stats_id] AS [statsID], [stat_name] AS [Statistic_Name]
		FROM #tblStatsUpd AS su INNER JOIN master.sys.databases AS sd (NOLOCK) ON su.[databaseID] = sd.[database_id] 
		WHERE sd.is_auto_update_stats_on = 0
		ORDER BY [DatabaseName], [tableName], [stats_id] DESC
	END;

	IF (SELECT COUNT(*) FROM #tblStatsUpd AS su INNER JOIN master.sys.databases AS sd ON su.[databaseID] = sd.[database_id] WHERE sd.is_auto_update_stats_on = 1) > 0
	BEGIN
		SELECT 'Statistics_to_update' AS [Check], '[WARNING: Some databases have Auto_Update_Statistics ENABLED and statistics that might need to be updated]' AS [Deviation]
		SELECT 'Statistics_to_update' AS [Information], [DatabaseName] AS [Database_Name], schemaName, [tableName] AS [Table_Name], [rows], modification_counter, [stats_id] AS [statsID], [stat_name] AS [Statistic_Name]
		FROM #tblStatsUpd AS su INNER JOIN master.sys.databases AS sd (NOLOCK) ON su.[databaseID] = sd.[database_id] 
		WHERE sd.is_auto_update_stats_on = 1
		ORDER BY [DatabaseName], [tableName], [stats_id] DESC
	END;
END
ELSE
BEGIN
	SELECT 'Statistics_to_update' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Hypothetical objects subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Hypothetical objects subsection', 10, 1) WITH NOWAIT

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs1%')
DROP TABLE #tmpdbs1
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs1%')
CREATE TABLE #tmpdbs1 (id int IDENTITY(1,1), [dbid] int, [dbname] VARCHAR(1000), isdone bit)

INSERT INTO #tmpdbs1 ([dbid], [dbname], isdone)
SELECT database_id, name, 0 FROM master.sys.databases (NOLOCK) WHERE is_read_only = 0 AND state = 0 AND database_id > 4 AND is_distributor = 0;

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblHypObj%')
DROP TABLE #tblHypObj;
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblHypObj%')
CREATE TABLE #tblHypObj ([DBName] sysname, [Schema] VARCHAR(100), [Table] VARCHAR(255), [Object] VARCHAR(255), [Type] VARCHAR(10));

WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT ''' + @dbname + ''' AS [DBName], QUOTENAME(t.name), QUOTENAME(o.[name]), i.name, ''INDEX'' FROM sys.indexes i 
INNER JOIN sys.objects o ON o.[object_id] = i.[object_id] 
INNER JOIN sys.tables AS mst ON mst.[object_id] = i.[object_id]
INNER JOIN sys.schemas AS t ON t.[schema_id] = mst.[schema_id]
WHERE i.is_hypothetical = 1
UNION ALL
SELECT ''' + @dbname + ''' AS [DBName], QUOTENAME(t.name), QUOTENAME(o.[name]), s.name, ''STATISTICS'' FROM sys.stats s 
INNER JOIN sys.objects o (NOLOCK) ON o.[object_id] = s.[object_id]
INNER JOIN sys.tables AS mst (NOLOCK) ON mst.[object_id] = s.[object_id]
INNER JOIN sys.schemas AS t (NOLOCK) ON t.[schema_id] = mst.[schema_id]
WHERE s.name LIKE ''hind_%'' AND auto_created = 0'

	BEGIN TRY
		INSERT INTO #tblHypObj
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Hypothetical objects subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
		
	UPDATE #tmpdbs1
	SET isdone = 1
	WHERE dbid = @dbid
END	

IF (SELECT COUNT([Object]) FROM #tblHypObj) > 0
BEGIN
	SELECT 'Hypothetical_objects' AS [Check], '[WARNING: Some databases have indexes or statistics that are marked as hypothetical. It is recommended to drop these objects as soon as possible]' AS [Deviation]
	SELECT 'Hypothetical_objects' AS [Information], DBName AS [Database_Name], [Table] AS [Table_Name], [Object] AS [Object_Name], [Type] AS [Object_Type]
	FROM #tblHypObj
	ORDER BY 2, 3, 5
		
	DECLARE @strSQL NVARCHAR(4000)
	PRINT CHAR(10) + '/* Generated on ' + CONVERT (VARCHAR, GETDATE()) + ' in ' + @@SERVERNAME + ' */'
	PRINT CHAR(10) + '--############# Existing Hypothetical objects drop statements #############' + CHAR(10)
	DECLARE ITW_Stats CURSOR FAST_FORWARD FOR SELECT 'USE ' + [DBName] + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sys.indexes WHERE name = N'''+ [Object] + ''')' + CHAR(10) +
	CASE WHEN [Type] = 'STATISTICS' THEN 'DROP STATISTICS ' + QUOTENAME([Schema]) + '.' + [Table] + '.' + QUOTENAME([Object]) + ';' + CHAR(10) + 'GO' + CHAR(10)
		ELSE 'DROP INDEX ' + QUOTENAME([Object]) + ' ON ' + QUOTENAME([Schema]) + '.' + [Table] + ';' + CHAR(10) + 'GO' + CHAR(10) 
		END
	FROM #tblHypObj
	ORDER BY DBName, [Table]
		
	OPEN ITW_Stats
	FETCH NEXT FROM ITW_Stats INTO @strSQL
	WHILE (@@FETCH_STATUS = 0)
	BEGIN
		PRINT @strSQL
		FETCH NEXT FROM ITW_Stats INTO @strSQL
	END
	CLOSE ITW_Stats
	DEALLOCATE ITW_Stats
	PRINT CHAR(10) + '--############# Ended Hypothetical objects drop statements #############' + CHAR(10)
END
ELSE
BEGIN
	SELECT 'Hypothetical_objects' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Duplicate or Redundant indexes subsection (clustered, non-clustered, clustered and non-clustered columnstore indexes only)
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Duplicate or Redundant indexes subsection', 10, 1) WITH NOWAIT
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs1%')
DROP TABLE #tblIxs1;
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs1%')
CREATE TABLE #tblIxs1 ([databaseID] int, [DatabaseName] sysname, [objectID] int, [schemaName] VARCHAR(100), [objectName] VARCHAR(200), 
	[indexID] int, [indexName] VARCHAR(200), [indexType] tinyint, [is_unique_constraint] bit, is_unique bit, is_disabled bit, fill_factor tinyint, is_padded bit, has_filter bit, filter_definition NVARCHAR(max),
	KeyCols VARCHAR(4000), KeyColsOrdered VARCHAR(4000), IncludedCols VARCHAR(4000) NULL, IncludedColsOrdered VARCHAR(4000) NULL, AllColsOrdered VARCHAR(4000) NULL, [KeyCols_data_length_bytes] int,
	CONSTRAINT PK_Ixs PRIMARY KEY CLUSTERED(databaseID, [objectID], [indexID]));

UPDATE #tmpdbs1
SET isdone = 0

WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT ' + CONVERT(VARCHAR(8), @dbid) + ' AS Database_ID, ''' + @dbname + ''' AS Database_Name,
	mst.[object_id] AS objectID, t.name AS schemaName, mst.[name] AS objectName, mi.index_id AS indexID, 
	mi.[name] AS Index_Name, mi.[type] AS [indexType], mi.[is_unique_constraint], mi.is_unique, mi.is_disabled,
	mi.fill_factor, mi.is_padded, ' + CASE WHEN @sqlmajorver > 9 THEN 'mi.has_filter, mi.filter_definition,' ELSE 'NULL, NULL,' END + ' 
	SUBSTRING(( SELECT '','' + ac.name FROM sys.tables AS st
		INNER JOIN sys.indexes AS i ON st.[object_id] = i.[object_id]
		INNER JOIN sys.index_columns AS ic ON i.[object_id] = ic.[object_id] AND i.[index_id] = ic.[index_id] 
		INNER JOIN sys.all_columns AS ac ON st.[object_id] = ac.[object_id] AND ic.[column_id] = ac.[column_id]
		WHERE mi.[object_id] = i.[object_id] AND mi.index_id = i.index_id AND ic.is_included_column = 0
		ORDER BY ic.key_ordinal
	FOR XML PATH('''')), 2, 8000) AS KeyCols,
	SUBSTRING(( SELECT '','' + ac.name FROM sys.tables AS st
		INNER JOIN sys.indexes AS i ON st.[object_id] = i.[object_id]
		INNER JOIN sys.index_columns AS ic ON i.[object_id] = ic.[object_id] AND i.[index_id] = ic.[index_id] 
		INNER JOIN sys.all_columns AS ac ON st.[object_id] = ac.[object_id] AND ic.[column_id] = ac.[column_id]
		WHERE mi.[object_id] = i.[object_id] AND mi.index_id = i.index_id AND ic.is_included_column = 0
		ORDER BY ac.name
	FOR XML PATH('''')), 2, 8000) AS KeyColsOrdered,
	SUBSTRING((SELECT '','' + ac.name FROM sys.tables AS st
		INNER JOIN sys.indexes AS i ON st.[object_id] = i.[object_id]
		INNER JOIN sys.index_columns AS ic ON i.[object_id] = ic.[object_id] AND i.[index_id] = ic.[index_id]
		INNER JOIN sys.all_columns AS ac ON st.[object_id] = ac.[object_id] AND ic.[column_id] = ac.[column_id]
		WHERE mi.[object_id] = i.[object_id] AND mi.index_id = i.index_id AND ic.is_included_column = 1
		ORDER BY ic.key_ordinal
	FOR XML PATH('''')), 2, 8000) AS IncludedCols,
	SUBSTRING((SELECT '','' + ac.name FROM sys.tables AS st
		INNER JOIN sys.indexes AS i ON st.[object_id] = i.[object_id]
		INNER JOIN sys.index_columns AS ic ON i.[object_id] = ic.[object_id] AND i.[index_id] = ic.[index_id]
		INNER JOIN sys.all_columns AS ac ON st.[object_id] = ac.[object_id] AND ic.[column_id] = ac.[column_id]
		WHERE mi.[object_id] = i.[object_id] AND mi.index_id = i.index_id AND ic.is_included_column = 1
		ORDER BY ac.name
	FOR XML PATH('''')), 2, 8000) AS IncludedColsOrdered,
	SUBSTRING((SELECT '','' + ac.name FROM sys.tables AS st
		INNER JOIN sys.indexes AS i ON st.[object_id] = i.[object_id]
		INNER JOIN sys.index_columns AS ic ON i.[object_id] = ic.[object_id] AND i.[index_id] = ic.[index_id]
		INNER JOIN sys.all_columns AS ac ON st.[object_id] = ac.[object_id] AND ic.[column_id] = ac.[column_id]
		WHERE mi.[object_id] = i.[object_id] AND mi.index_id = i.index_id
		ORDER BY ac.name
	FOR XML PATH('''')), 2, 8000) AS AllColsOrdered,
	(SELECT SUM(CASE sty.name WHEN ''nvarchar'' THEN sc.max_length/2 ELSE sc.max_length END) FROM sys.indexes AS i
		INNER JOIN sys.tables AS t ON t.[object_id] = i.[object_id]
		INNER JOIN sys.schemas ss ON ss.[schema_id] = t.[schema_id]
		INNER JOIN sys.index_columns AS sic ON sic.object_id = mst.object_id AND sic.index_id = mi.index_id
		INNER JOIN sys.columns AS sc ON sc.object_id = t.object_id AND sc.column_id = sic.column_id
		INNER JOIN sys.types AS sty ON sc.user_type_id = sty.user_type_id
		WHERE mi.[object_id] = i.[object_id] AND mi.index_id = i.index_id AND sic.key_ordinal > 0) AS [KeyCols_data_length_bytes]
FROM sys.indexes AS mi
INNER JOIN sys.tables AS mst ON mst.[object_id] = mi.[object_id]
INNER JOIN sys.schemas AS t ON t.[schema_id] = mst.[schema_id]
WHERE mi.type IN (1,2,5,6) AND mi.is_unique_constraint = 0
	AND mst.is_ms_shipped = 0
	--AND OBJECTPROPERTY(o.object_id,''IsUserTable'') = 1 -- sys.tables only returns type U
ORDER BY objectName;'

	BEGIN TRY
		INSERT INTO #tblIxs1
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Duplicate or Redundant indexes subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
		
	UPDATE #tmpdbs1
	SET isdone = 1
	WHERE dbid = @dbid
END

IF (SELECT COUNT(*) FROM #tblIxs1 I INNER JOIN #tblIxs1 I2 ON I.[databaseID] = I2.[databaseID] AND I.[objectID] = I2.[objectID] AND I.[indexID] <> I2.[indexID] 
	AND I.[KeyCols] = I2.[KeyCols] AND (I.IncludedCols = I2.IncludedCols OR (I.IncludedCols IS NULL AND I2.IncludedCols IS NULL))) > 0
BEGIN
	SELECT 'Duplicate_Indexes' AS [Check], '[WARNING: Some databases have duplicate indexes. It is recommended to revise the need to maintain all these objects as soon as possible]' AS [Deviation]
	SELECT 'Duplicate_Indexes' AS [Information], I.[DatabaseName] AS [Database_Name], I.schemaName, I.[objectName] AS [Table_Name], 
		I.[indexID], I.[indexName] AS [Index_Name], I.is_unique, I.fill_factor, I.is_padded, I.has_filter, I.filter_definition,
		I.KeyCols, I.IncludedCols, CASE WHEN I.IncludedCols IS NULL THEN I.[KeyCols] ELSE I.[KeyCols] + ',' + I.IncludedCols END AS [AllColsOrdered]
	FROM #tblIxs1 I INNER JOIN #tblIxs1 I2
		ON I.[databaseID] = I2.[databaseID] AND I.[objectID] = I2.[objectID] AND I.[indexID] <> I2.[indexID] 
		AND I.[KeyCols] = I2.[KeyCols] AND (I.IncludedCols = I2.IncludedCols OR (I.IncludedCols IS NULL AND I2.IncludedCols IS NULL))
	GROUP BY I.[databaseID], I.[DatabaseName], I.[schemaName], I.[objectName], I.[indexID], I.[indexName], I.KeyCols, I.IncludedCols, I.[KeyColsOrdered], I.IncludedColsOrdered, I.is_unique, I.fill_factor, I.is_padded, I.has_filter, I.filter_definition
	ORDER BY I.DatabaseName, I.[objectName], I.[indexID]
		
	DECLARE @strSQL2 NVARCHAR(4000)
	PRINT CHAR(10) + '/* Generated on ' + CONVERT (VARCHAR, GETDATE()) + ' in ' + @@SERVERNAME + ' */'
	PRINT CHAR(10) + '--############# Existing Duplicate indexes drop statements #############' + CHAR(10)
	DECLARE Dup_Stats CURSOR FAST_FORWARD FOR SELECT 'USE ' + I.[DatabaseName] + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sys.indexes WHERE name = N'''+ I.[indexName] + ''')' + CHAR(10) +
	'DROP INDEX ' + QUOTENAME(I.[indexName]) + ' ON ' + QUOTENAME(I.[schemaName]) + '.' + QUOTENAME(I.[objectName]) + ';' + CHAR(10) + 'GO' + CHAR(10) 
	FROM #tblIxs1 I INNER JOIN #tblIxs1 I2
		ON I.[databaseID] = I2.[databaseID] AND I.[objectID] = I2.[objectID] AND I.[indexID] <> I2.[indexID] 
		AND I.[KeyCols] = I2.[KeyCols] AND (I.IncludedCols = I2.IncludedCols OR (I.IncludedCols IS NULL AND I2.IncludedCols IS NULL))
	WHERE I.[indexID] NOT IN (
		SELECT MIN(tI.[indexID]) FROM #tblIxs1 tI INNER JOIN #tblIxs1 tI2
			ON tI.[databaseID] = tI2.[databaseID] AND tI.[objectID] = tI2.[objectID] AND tI.[indexID] <> tI2.[indexID] 
			AND tI.[KeyCols] = tI2.[KeyCols] AND (tI.IncludedCols = tI2.IncludedCols OR (tI.IncludedCols IS NULL AND tI2.IncludedCols IS NULL))
		WHERE tI.[databaseID] = I.[databaseID] AND tI.[objectID] = I.[objectID]
		GROUP BY tI.[databaseID], tI.[DatabaseName], tI.[objectName], tI.KeyCols, tI.IncludedCols, tI.[KeyColsOrdered], tI.IncludedColsOrdered
		)
	GROUP BY I.[databaseID], I.[DatabaseName], I.[schemaName], I.[objectName], I.[indexID], I.[indexName], I.KeyCols, I.IncludedCols, I.[KeyColsOrdered], I.IncludedColsOrdered
	ORDER BY I.DatabaseName, I.[objectName], I.[indexID]

	OPEN Dup_Stats
	FETCH NEXT FROM Dup_Stats INTO @strSQL2
	WHILE (@@FETCH_STATUS = 0)
	BEGIN
		PRINT @strSQL2
		FETCH NEXT FROM Dup_Stats INTO @strSQL2
	END
	CLOSE Dup_Stats
	DEALLOCATE Dup_Stats
	PRINT '--############# Ended Duplicate indexes drop statements #############' + CHAR(10)
END
ELSE
BEGIN
	SELECT 'Duplicate_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

IF (SELECT COUNT(*) FROM #tblIxs1 I INNER JOIN #tblIxs1 I2 ON I.[databaseID] = I2.[databaseID] AND I.[objectID] = I2.[objectID] AND I.[indexID] <> I2.[indexID] 
	AND (I.[KeyCols] <> I2.[KeyCols] OR I.IncludedCols <> I2.IncludedCols)
	AND (((I.[KeyColsOrdered] <> I2.[KeyColsOrdered] OR I.IncludedColsOrdered <> I2.IncludedColsOrdered)
			AND ((CASE WHEN I.IncludedColsOrdered IS NULL THEN I.[KeyColsOrdered] ELSE I.[KeyColsOrdered] + ',' + I.IncludedColsOrdered END) = (CASE WHEN I2.IncludedColsOrdered IS NULL THEN I2.[KeyColsOrdered] ELSE I2.[KeyColsOrdered] + ',' + I2.IncludedColsOrdered END)
				OR I.[AllColsOrdered] = I2.[AllColsOrdered]))
		OR (I.[KeyColsOrdered] <> I2.[KeyColsOrdered] AND I.IncludedColsOrdered = I2.IncludedColsOrdered)
		OR (I.[KeyColsOrdered] = I2.[KeyColsOrdered] AND I.IncludedColsOrdered <> I2.IncludedColsOrdered))
	AND I.indexID NOT IN (SELECT I3.[indexID]
		FROM #tblIxs1 I3 INNER JOIN #tblIxs1 I4
		ON I3.[databaseID] = I4.[databaseID] AND I3.[objectID] = I4.[objectID] AND I3.[indexID] <> I4.[indexID] 
			AND I3.[KeyCols] = I4.[KeyCols] AND (I3.IncludedCols = I4.IncludedCols OR (I3.IncludedCols IS NULL AND I4.IncludedCols IS NULL))
		WHERE I3.[databaseID] = I.[databaseID] AND I3.[objectID] = I.[objectID]
		GROUP BY I3.[indexID])
	WHERE I.indexType IN (1,2,5,6)		-- clustered, non-clustered, clustered and non-clustered columnstore indexes only
		AND I2.indexType IN (1,2,5,6)	-- clustered, non-clustered, clustered and non-clustered columnstore indexes only
		AND I.is_unique_constraint = 0	-- no unique constraints
		AND I2.is_unique_constraint = 0	-- no unique constraints
	) > 0
BEGIN
	SELECT 'Redundant_Indexes' AS [Check], '[WARNING: Some databases have possibly redundant indexes. It is recommended to revise the need to maintain all these objects as soon as possible]' AS [Deviation]
	SELECT 'Redundant_Indexes' AS [Information], I.[DatabaseName] AS [Database_Name], I.schemaName, I.[objectName] AS [Table_Name],
		I.[indexID], I.[indexName] AS [Index_Name], I.is_unique, I.fill_factor, I.is_padded, I.has_filter, I.filter_definition,
		I.KeyCols, I.IncludedCols, CASE WHEN I.IncludedColsOrdered IS NULL THEN I.[KeyColsOrdered] ELSE I.[KeyColsOrdered] + ',' + I.IncludedColsOrdered END AS [KeyInclColsOrdered]
	FROM #tblIxs1 I INNER JOIN #tblIxs1 I2
	ON I.[databaseID] = I2.[databaseID] AND I.[objectID] = I2.[objectID] AND I.[indexID] <> I2.[indexID] 
		AND (((I.[KeyColsOrdered] <> I2.[KeyColsOrdered] OR I.IncludedColsOrdered <> I2.IncludedColsOrdered)
			AND ((CASE WHEN I.IncludedColsOrdered IS NULL THEN I.[KeyColsOrdered] ELSE I.[KeyColsOrdered] + ',' + I.IncludedColsOrdered END) = (CASE WHEN I2.IncludedColsOrdered IS NULL THEN I2.[KeyColsOrdered] ELSE I2.[KeyColsOrdered] + ',' + I2.IncludedColsOrdered END)
				OR I.[AllColsOrdered] = I2.[AllColsOrdered]))
		OR (I.[KeyColsOrdered] <> I2.[KeyColsOrdered] AND I.IncludedColsOrdered = I2.IncludedColsOrdered)
		OR (I.[KeyColsOrdered] = I2.[KeyColsOrdered] AND I.IncludedColsOrdered <> I2.IncludedColsOrdered))
		AND I.indexID NOT IN (SELECT I3.[indexID]
			FROM #tblIxs1 I3 INNER JOIN #tblIxs1 I4
			ON I3.[databaseID] = I4.[databaseID] AND I3.[objectID] = I4.[objectID] AND I3.[indexID] <> I4.[indexID] 
				AND I3.[KeyCols] = I4.[KeyCols] AND (I3.IncludedCols = I4.IncludedCols OR (I3.IncludedCols IS NULL AND I4.IncludedCols IS NULL))
			WHERE I3.[databaseID] = I.[databaseID] AND I3.[objectID] = I.[objectID]
			GROUP BY I3.[indexID])
	WHERE I.indexType IN (1,2,5,6)		-- clustered, non-clustered, clustered and non-clustered columnstore indexes only
		AND I2.indexType IN (1,2,5,6)	-- clustered, non-clustered, clustered and non-clustered columnstore indexes only
		AND I.is_unique_constraint = 0	-- no unique constraints
		AND I2.is_unique_constraint = 0	-- no unique constraints
	GROUP BY I.[DatabaseName], I.[schemaName], I.[objectName], I.[indexID], I.[indexName], I.KeyCols, I.IncludedCols, I.[KeyColsOrdered], I.IncludedColsOrdered, I.is_unique, I.fill_factor, I.is_padded, I.has_filter, I.filter_definition
	ORDER BY I.DatabaseName, I.[objectName], I.[KeyColsOrdered], I.IncludedColsOrdered, I.[indexID]
END
ELSE
BEGIN
	SELECT 'Redundant_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Unused and rarely used indexes subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Unused and rarely used indexes subsection', 10, 1) WITH NOWAIT
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs2%')
DROP TABLE #tblIxs2
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs2%')
CREATE TABLE #tblIxs2 ([databaseID] int, [DatabaseName] sysname, [objectID] int, [schemaName] VARCHAR(100), [objectName] VARCHAR(200), 
	[indexID] int, [indexName] VARCHAR(200), [Hits] bigint NULL, [Reads_Ratio] DECIMAL(5,2), [Writes_Ratio] DECIMAL(5,2),
	user_updates bigint, last_user_seek DATETIME NULL, last_user_scan DATETIME NULL, last_user_lookup DATETIME NULL, 
	last_user_update DATETIME NULL, is_unique bit, [type] tinyint, is_primary_key bit, is_unique_constraint bit, is_disabled bit,
	CONSTRAINT PK_Ixs2 PRIMARY KEY CLUSTERED(databaseID, [objectID], [indexID]))

UPDATE #tmpdbs1
SET isdone = 0

WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT ' + CONVERT(VARCHAR(8), @dbid) + ' AS Database_ID, ''' + @dbname + ''' AS Database_Name,
	mst.[object_id] AS objectID, t.name AS schemaName, mst.[name] AS objectName, si.index_id AS indexID, si.[name] AS Index_Name,
	(s.user_seeks + s.user_scans + s.user_lookups) AS [Hits],
	RTRIM(CONVERT(NVARCHAR(10),CAST(CASE WHEN (s.user_seeks + s.user_scans + s.user_lookups) = 0 THEN 0 ELSE CONVERT(REAL, (s.user_seeks + s.user_scans + s.user_lookups)) * 100 /
		CASE (s.user_seeks + s.user_scans + s.user_lookups + s.user_updates) WHEN 0 THEN 1 ELSE CONVERT(REAL, (s.user_seeks + s.user_scans + s.user_lookups + s.user_updates)) END END AS DECIMAL(18,2)))) AS [Reads_Ratio],
	RTRIM(CONVERT(NVARCHAR(10),CAST(CASE WHEN s.user_updates = 0 THEN 0 ELSE CONVERT(REAL, s.user_updates) * 100 /
		CASE (s.user_seeks + s.user_scans + s.user_lookups + s.user_updates) WHEN 0 THEN 1 ELSE CONVERT(REAL, (s.user_seeks + s.user_scans + s.user_lookups + s.user_updates)) END END AS DECIMAL(18,2)))) AS [Writes_Ratio],
	s.user_updates,
	MAX(s.last_user_seek) AS last_user_seek,
	MAX(s.last_user_scan) AS last_user_scan,
	MAX(s.last_user_lookup) AS last_user_lookup,
	MAX(s.last_user_update) AS last_user_update,
	si.is_unique, si.[type], si.is_primary_key, si.is_unique_constraint, si.is_disabled	
FROM sys.indexes AS si (NOLOCK)
INNER JOIN sys.objects AS o (NOLOCK) ON si.[object_id] = o.[object_id]
INNER JOIN sys.tables AS mst (NOLOCK) ON mst.[object_id] = si.[object_id]
INNER JOIN sys.schemas AS t (NOLOCK) ON t.[schema_id] = mst.[schema_id]
INNER JOIN sys.dm_db_index_usage_stats AS s (NOLOCK) ON s.database_id = ' + CONVERT(VARCHAR(8), @dbid) + ' 
	AND s.object_id = si.object_id AND s.index_id = si.index_id
WHERE mst.is_ms_shipped = 0
	--AND OBJECTPROPERTY(o.object_id,''IsUserTable'') = 1 -- sys.tables only returns type U
	AND si.type IN (2,6) 			-- non-clustered and non-clustered columnstore indexes only
	AND si.is_primary_key = 0 		-- no primary keys
	AND si.is_unique_constraint = 0	-- no unique constraints
	AND si.is_unique = 0 			-- no alternate keys
GROUP BY mst.[object_id], t.[name], mst.[name], si.index_id, si.[name], s.user_seeks, s.user_scans, s.user_lookups, s.user_updates, si.is_unique,
	si.[type], si.is_primary_key, si.is_unique_constraint, si.is_disabled
ORDER BY objectName	
OPTION (MAXDOP 2);'
	BEGIN TRY
		INSERT INTO #tblIxs2
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Unused and rarely used indexes subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
		
	UPDATE #tmpdbs1
	SET isdone = 1
	WHERE dbid = @dbid
END

UPDATE #tmpdbs1
SET isdone = 0

WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT ' + CONVERT(VARCHAR(8), @dbid) + ' AS Database_ID, ''' + @dbname + ''' AS Database_Name, 
	si.[object_id] AS objectID, t.name AS schemaName, OBJECT_NAME(si.[object_id], ' + CONVERT(VARCHAR(8), @dbid) + ') AS objectName, si.index_id AS indexID, 
	si.[name] AS Index_Name, 0, 0, 0, 0, NULL, NULL, NULL, NULL,
	si.is_unique, si.[type], si.is_primary_key, si.is_unique_constraint, si.is_disabled
FROM sys.indexes AS si (NOLOCK)
INNER JOIN sys.objects AS so (NOLOCK) ON si.object_id = so.object_id 
INNER JOIN sys.tables AS mst (NOLOCK) ON mst.[object_id] = si.[object_id]
INNER JOIN sys.schemas AS t (NOLOCK) ON t.[schema_id] = mst.[schema_id]
WHERE OBJECTPROPERTY(so.object_id,''IsUserTable'') = 1
	AND mst.is_ms_shipped = 0
	AND si.index_id NOT IN (SELECT s.index_id
		FROM sys.dm_db_index_usage_stats s
		WHERE s.object_id = si.object_id 
			AND si.index_id = s.index_id 
			AND database_id = ' + CONVERT(VARCHAR(8), @dbid) + ')
	AND si.name IS NOT NULL
	AND si.type IN (2,6) 			-- non-clustered and non-clustered columnstore indexes only
	AND si.is_primary_key = 0 		-- no primary keys
	AND si.is_unique_constraint = 0	-- no unique constraints
	AND si.is_unique = 0 			-- no alternate keys'

	BEGIN TRY
		INSERT INTO #tblIxs2
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Unused and rarely used indexes subsection - Error raised in TRY block 2. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH

	UPDATE #tmpdbs1
	SET isdone = 1
	WHERE dbid = @dbid
END	

IF (SELECT COUNT(*) FROM #tblIxs2 WHERE [Hits] = 0 /*AND is_disabled = 0*/) > 0
BEGIN
	SELECT 'Unused_Indexes' AS [Check], '[WARNING: Some databases have unused indexes. It is recommended to revise the need to maintain all these objects as soon as possible]' AS [Deviation]
	SELECT 'Unused_Indexes_With_Updates' AS [Information], [DatabaseName] AS [Database_Name], schemaName, [objectName] AS [Table_Name], [indexID], [indexName] AS [Index_Name], is_unique, 
	[Hits], CONVERT(NVARCHAR,[Reads_Ratio]) COLLATE database_default + '/' + CONVERT(NVARCHAR,[Writes_Ratio]) COLLATE database_default AS [R/W_Ratio],
	user_updates, last_user_seek, last_user_scan, last_user_lookup, last_user_update
	FROM #tblIxs2
	WHERE [Hits] = 0 AND last_user_update > 0
	UNION ALL
	SELECT 'Unused_Indexes_No_Updates' AS [Information], [DatabaseName] AS [Database_Name], schemaName, [objectName] AS [Table_Name], [indexID], [indexName] AS [Index_Name], is_unique, 
	[Hits], CONVERT(NVARCHAR,[Reads_Ratio]) COLLATE database_default + '/' + CONVERT(NVARCHAR,[Writes_Ratio]) COLLATE database_default AS [R/W_Ratio],
	user_updates, last_user_seek, last_user_scan, last_user_lookup, last_user_update
	FROM #tblIxs2
	WHERE [Hits] = 0 AND (last_user_update = 0 OR last_user_update IS NULL)
	ORDER BY [Information], [Database_Name], [Table_Name], [R/W_Ratio] DESC;

	DECLARE @strSQL3 NVARCHAR(4000)
	PRINT CHAR(10) + '/* Generated on ' + CONVERT (VARCHAR, GETDATE()) + ' in ' + @@SERVERNAME + ' */'
		
	IF (SELECT COUNT(*) FROM #tblIxs2 WHERE [Hits] = 0 AND last_user_update > 0) > 0
	BEGIN
		PRINT CHAR(10) + '--############# Existing unused indexes with updates drop statements #############' + CHAR(10)
		DECLARE Un_Stats CURSOR FAST_FORWARD FOR SELECT 'USE ' + [DatabaseName] + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sys.indexes WHERE name = N'''+ [indexName] + ''')' + CHAR(10) +
		'DROP INDEX ' + QUOTENAME([indexName]) + ' ON ' + QUOTENAME([schemaName]) + '.' + QUOTENAME([objectName]) + ';' + CHAR(10) + 'GO' + CHAR(10) 
		FROM #tblIxs2
		WHERE [Hits] = 0 AND last_user_update > 0
		ORDER BY [DatabaseName], [objectName], [Reads_Ratio] DESC;

		OPEN Un_Stats
		FETCH NEXT FROM Un_Stats INTO @strSQL3
		WHILE (@@FETCH_STATUS = 0)
		BEGIN
			PRINT @strSQL3
			FETCH NEXT FROM Un_Stats INTO @strSQL3
		END
		CLOSE Un_Stats
		DEALLOCATE Un_Stats
		PRINT CHAR(10) + '--############# Ended unused indexes with updates drop statements #############' + CHAR(10)
	END;

	IF (SELECT COUNT(*) FROM #tblIxs2 WHERE [Hits] = 0 AND (last_user_update = 0 OR last_user_update IS NULL)) > 0
	BEGIN
		PRINT CHAR(10) + '--############# Existing unused indexes with no updates drop statements #############' + CHAR(10)
		DECLARE Un_Stats CURSOR FAST_FORWARD FOR SELECT 'USE ' + [DatabaseName] + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sys.indexes WHERE name = N'''+ [indexName] + ''')' + CHAR(10) +
		'DROP INDEX ' + QUOTENAME([indexName]) + ' ON ' + QUOTENAME([schemaName]) + '.' + QUOTENAME([objectName]) + ';' + CHAR(10) + 'GO' + CHAR(10) 
		FROM #tblIxs2
		WHERE [Hits] = 0 AND (last_user_update = 0 OR last_user_update IS NULL)
		ORDER BY [DatabaseName], [objectName], [Reads_Ratio] DESC;

		OPEN Un_Stats
		FETCH NEXT FROM Un_Stats INTO @strSQL3
		WHILE (@@FETCH_STATUS = 0)
		BEGIN
			PRINT @strSQL3
			FETCH NEXT FROM Un_Stats INTO @strSQL3
		END
		CLOSE Un_Stats
		DEALLOCATE Un_Stats
		PRINT CHAR(10) + '--############# Ended unused indexes with no updates drop statements #############' + CHAR(10)
	END
END
ELSE
BEGIN
	SELECT 'Unused_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

IF (SELECT COUNT(*) FROM #tblIxs2 WHERE [Hits] > 0 AND [Reads_Ratio] < 5 AND type IN (1,2,5,6) AND is_primary_key = 0 AND is_unique_constraint = 0 /*AND is_disabled = 0*/) > 0
BEGIN
	SELECT 'Rarely_Used_Indexes' AS [Check], '[WARNING: Some databases have rarely used indexes. It is recommended to revise the need to maintain all these objects as soon as possible]' AS [Deviation]
	SELECT 'Rarely_Used_Indexes' AS [Information], [DatabaseName] AS [Database_Name], schemaName, [objectName] AS [Table_Name], [indexID], [indexName] AS [Index_Name], is_unique, 
	[Hits], CONVERT(NVARCHAR,[Reads_Ratio]) COLLATE database_default + '/' + CONVERT(NVARCHAR,[Writes_Ratio]) COLLATE database_default AS [R/W_Ratio],
	user_updates, last_user_seek, last_user_scan, last_user_lookup, last_user_update
	FROM #tblIxs2
	WHERE [Hits] > 0 AND [Reads_Ratio] < 5
	ORDER BY [DatabaseName], [objectName], [Reads_Ratio] DESC
		
	DECLARE @strSQL4 NVARCHAR(4000)
	PRINT CHAR(10) + '/* Generated on ' + CONVERT (VARCHAR, GETDATE()) + ' in ' + @@SERVERNAME + ' */'
	PRINT CHAR(10) + '--############# Existing rarely used indexes drop statements #############' + CHAR(10)
	DECLARE curRarUsed CURSOR FAST_FORWARD FOR SELECT 'USE ' + [DatabaseName] + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sys.indexes WHERE name = N'''+ [indexName] + ''')' + CHAR(10) +
	'DROP INDEX ' + QUOTENAME([indexName]) + ' ON ' + QUOTENAME([schemaName]) + '.' + QUOTENAME([objectName]) + ';' + CHAR(10) + 'GO' + CHAR(10) 
	FROM #tblIxs2
	WHERE [Hits] > 0 AND [Reads_Ratio] < 5
	ORDER BY [DatabaseName], [objectName], [Reads_Ratio] DESC

	OPEN curRarUsed
	FETCH NEXT FROM curRarUsed INTO @strSQL4
	WHILE (@@FETCH_STATUS = 0)
	BEGIN
		PRINT @strSQL4
		FETCH NEXT FROM curRarUsed INTO @strSQL4
	END
	CLOSE curRarUsed
	DEALLOCATE curRarUsed
	PRINT '--############# Ended rarely used indexes drop statements #############' + CHAR(10)
END
ELSE
BEGIN
	SELECT 'Rarely_Used_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Indexes with large keys (> 900 bytes) subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Indexes with large keys (> 900 bytes) subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(*) FROM #tblIxs1 WHERE [KeyCols_data_length_bytes] > 900) > 0
BEGIN
	SELECT 'Large_Index_Key' AS [Check], '[WARNING: Some indexes have keys larger than 900 bytes. It is recommended to revise these]' AS [Deviation]
	SELECT 'Large_Index_Key' AS [Information], I.[DatabaseName] AS [Database_Name], I.schemaName, I.[objectName] AS [Table_Name], I.[indexID], I.[indexName] AS [Index_Name], 
		I.KeyCols, [KeyCols_data_length_bytes]
	FROM #tblIxs1 I
	WHERE [KeyCols_data_length_bytes] > 900
	ORDER BY I.[DatabaseName], I.schemaName, I.[objectName], I.[indexID]
END
ELSE
BEGIN
	SELECT 'Large_Index_Key' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Indexes with fill factor < 80 pct subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Indexes with fill factor < 80 pct subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(*) FROM #tblIxs1 WHERE [fill_factor] BETWEEN 1 AND 79) > 0
BEGIN
	SELECT 'Low_Fill_Factor' AS [Check], '[WARNING: Some indexes have a fill factor lower than 80 percent. Revise the need to maintain such a low value]' AS [Deviation]
	SELECT 'Low_Fill_Factor' AS [Information], I.[DatabaseName] AS [Database_Name], I.schemaName, I.[objectName] AS [Table_Name], I.[indexID], I.[indexName] AS [Index_Name], 
		[fill_factor], I.KeyCols, I.IncludedCols, CASE WHEN I.IncludedCols IS NULL THEN I.[KeyCols] ELSE I.[KeyCols] + ',' + I.IncludedCols END AS [AllColsOrdered]
	FROM #tblIxs1 I
	WHERE [fill_factor] BETWEEN 1 AND 79
	ORDER BY I.[DatabaseName], I.schemaName, I.[objectName], I.[indexID]
END
ELSE
BEGIN
	SELECT 'Low_Fill_Factor' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Disabled indexes subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting disabled indexes subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(*) FROM #tblIxs1 WHERE [is_disabled] = 1) > 0
BEGIN
	SELECT 'Disabled_IXs' AS [Check], '[WARNING: Some indexes are disabled. Revise the need to maintain these]' AS [Deviation]
	SELECT 'Disabled_IXs' AS [Information], I.[DatabaseName] AS [Database_Name], I.schemaName, I.[objectName] AS [Table_Name], I.[indexID], I.[indexName] AS [Index_Name], 
		CASE WHEN [indexType] = 1 THEN 'Clustered' 
		WHEN [indexType] = 2 THEN 'Non-clustered'
		WHEN [indexType] = 3 THEN 'Clustered columnstore'
		ELSE 'Non-clustered columnstore' END AS [Index_Type],
	I.KeyCols, I.IncludedCols, CASE WHEN I.IncludedCols IS NULL THEN I.[KeyCols] ELSE I.[KeyCols] + ',' + I.IncludedCols END AS [AllColsOrdered]
	FROM #tblIxs1 I
	WHERE [is_disabled] = 1
	ORDER BY I.[DatabaseName], I.schemaName, I.[objectName], I.[indexID]
END
ELSE
BEGIN
	SELECT 'Disabled_IXs' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Non-unique clustered indexes subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Non-unique clustered indexes subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(*) FROM #tblIxs1 WHERE [is_unique] = 0 AND indexID = 1) > 0
BEGIN
	SELECT 'NonUnique_CIXs' AS [Check], '[WARNING: Some clustered indexes are non-unique. Revise the need to have non-unique clustering keys to which a uniquefier is added]' AS [Deviation]
	SELECT 'NonUnique_CIXs' AS [Information], I.[DatabaseName] AS [Database_Name], I.schemaName, I.[objectName] AS [Table_Name], I.[indexID], I.[indexName] AS [Index_Name], 
		I.IncludedCols, CASE WHEN I.IncludedCols IS NULL THEN I.[KeyCols] ELSE I.[KeyCols] + ',' + I.IncludedCols END AS [AllColsOrdered]
	FROM #tblIxs1 I
	WHERE [is_unique] = 0 AND indexID = 1
	ORDER BY I.[DatabaseName], I.schemaName, I.[objectName]
END
ELSE
BEGIN
	SELECT 'NonUnique_CIXs' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Foreign Keys with no Index subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Foreign Keys with no Index subsection', 10, 1) WITH NOWAIT
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFK%')
DROP TABLE #tblFK
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFK%')
CREATE TABLE #tblFK ([databaseID] int, [DatabaseName] sysname, [constraint_name] VARCHAR(200), [parent_schema_name] VARCHAR(100), 
[parent_table_name] VARCHAR(200), parent_columns VARCHAR(4000), [referenced_schema] VARCHAR(100), [referenced_table_name] VARCHAR(200), referenced_columns VARCHAR(4000),
CONSTRAINT PK_FK PRIMARY KEY CLUSTERED(databaseID, [constraint_name]))
	
UPDATE #tmpdbs1
SET isdone = 0

WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + '
;WITH cteFK AS (
SELECT t.name AS [parent_schema_name],
	OBJECT_NAME(FKC.parent_object_id) [parent_table_name],
	OBJECT_NAME(constraint_object_id) AS [constraint_name],
	t2.name AS [referenced_schema],
	OBJECT_NAME(referenced_object_id) AS [referenced_table_name],
	SUBSTRING((SELECT '','' + COL_NAME(k.parent_object_id,parent_column_id) AS [data()]
		FROM sys.foreign_key_columns (NOLOCK) AS k
		INNER JOIN sys.foreign_keys (NOLOCK) ON k.constraint_object_id = [object_id]
			AND k.constraint_object_id = FKC.constraint_object_id
		ORDER BY constraint_column_id
		FOR XML PATH('''')), 2, 8000) AS [parent_columns],
	SUBSTRING((SELECT '','' + COL_NAME(k.referenced_object_id,referenced_column_id) AS [data()]
		FROM sys.foreign_key_columns (NOLOCK) AS k
		INNER JOIN sys.foreign_keys (NOLOCK) ON k.constraint_object_id = [object_id]
			AND k.constraint_object_id = FKC.constraint_object_id
		ORDER BY constraint_column_id
		FOR XML PATH('''')), 2, 8000) AS [referenced_columns]
FROM sys.foreign_key_columns FKC (NOLOCK)
INNER JOIN sys.objects o (NOLOCK) ON FKC.parent_object_id = o.[object_id]
INNER JOIN sys.tables mst (NOLOCK) ON mst.[object_id] = o.[object_id]
INNER JOIN sys.schemas t (NOLOCK) ON t.[schema_id] = mst.[schema_id]
INNER JOIN sys.objects so (NOLOCK) ON FKC.referenced_object_id = so.[object_id]
INNER JOIN sys.tables AS mst2 (NOLOCK) ON mst2.[object_id] = so.[object_id]
INNER JOIN sys.schemas AS t2 (NOLOCK) ON t2.[schema_id] = mst2.[schema_id]
WHERE o.type = ''U'' AND so.type = ''U''
GROUP BY o.[schema_id],so.[schema_id],FKC.parent_object_id,constraint_object_id,referenced_object_id,t.name,t2.name
),
cteIndexCols AS (
SELECT t.name AS schemaName,
OBJECT_NAME(mst.[object_id]) AS objectName,
SUBSTRING(( SELECT '','' + QUOTENAME(ac.name) FROM sys.tables AS st
	INNER JOIN sys.indexes AS mi ON st.[object_id] = mi.[object_id]
	INNER JOIN sys.index_columns AS ic ON mi.[object_id] = ic.[object_id] AND mi.[index_id] = ic.[index_id] 
	INNER JOIN sys.all_columns AS ac ON st.[object_id] = ac.[object_id] AND ic.[column_id] = ac.[column_id]
	WHERE i.[object_id] = mi.[object_id] AND i.index_id = mi.index_id AND ic.is_included_column = 0
	ORDER BY ac.name
FOR XML PATH('''')), 2, 8000) AS KeyCols
FROM sys.indexes AS i
INNER JOIN sys.tables AS mst ON mst.[object_id] = i.[object_id]
INNER JOIN sys.schemas AS t ON t.[schema_id] = mst.[schema_id]
WHERE i.type IN (1,2,5,6) AND i.is_unique_constraint = 0
	AND mst.is_ms_shipped = 0
)
SELECT ' + CONVERT(VARCHAR(8), @dbid) + ' AS Database_ID, ''' + @dbname + ''' AS Database_Name, fk.constraint_name AS constraintName,
	fk.parent_schema_name AS schemaName, fk.parent_table_name AS tableName,
	fk.parent_columns AS parentColumns, fk.referenced_schema AS referencedSchemaName,
	fk.referenced_table_name AS referencedTableName, fk.referenced_columns AS referencedColumns
FROM cteFK fk 
WHERE NOT EXISTS (SELECT 1 FROM cteIndexCols ict 
					WHERE fk.parent_schema_name = ict.schemaName
						AND fk.parent_table_name = ict.objectName 
						AND fk.parent_columns = ict.KeyCols);'
	BEGIN TRY
		INSERT INTO #tblFK
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Foreign Keys with no Index subsection - Error raised in TRY block. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH

	UPDATE #tmpdbs1
	SET isdone = 1
	WHERE dbid = @dbid
END	
	
IF (SELECT COUNT(*) FROM #tblFK) > 0
BEGIN
	SELECT 'FK_no_Index' AS [Check], '[WARNING: Some Foreign Key constraints are not supported by an Index. It is recommended to revise these]' AS [Deviation]
	SELECT 'FK_no_Index' AS [Information], FK.[DatabaseName] AS [Database_Name], constraint_name AS constraintName,
		FK.parent_schema_name AS schemaName, FK.parent_table_name AS [tableName],
		FK.parent_columns AS parentColumns, FK.referenced_schema AS referencedSchemaName,
		FK.referenced_table_name AS referencedTableName, FK.referenced_columns AS referencedColumns
	FROM #tblFK FK
	ORDER BY [DatabaseName], schemaName, tableName, referenced_schema, referenced_table_name

	DECLARE @strSQL5 NVARCHAR(4000)
	PRINT CHAR(10) + '/* Generated on ' + CONVERT (VARCHAR, GETDATE()) + ' in ' + @@SERVERNAME + ' */'
	PRINT CHAR(10) + '--############# FK index creation statements #############' + CHAR(10)
	DECLARE curFKs CURSOR FAST_FORWARD FOR SELECT 'USE ' + [DatabaseName] + CHAR(10) + 'GO' + CHAR(10) +
	'CREATE INDEX IX_' + REPLACE(constraint_name,' ','_') + ' ON ' + QUOTENAME(parent_schema_name) + '.' + QUOTENAME(parent_table_name) + ' (' + QUOTENAME(parent_columns) + ');' + CHAR(10) + 'GO' + CHAR(10) 
	FROM #tblFK
	ORDER BY [DatabaseName], parent_schema_name, parent_table_name, referenced_schema, referenced_table_name

	OPEN curFKs
	FETCH NEXT FROM curFKs INTO @strSQL5
	WHILE (@@FETCH_STATUS = 0)
	BEGIN
		PRINT @strSQL5
		FETCH NEXT FROM curFKs INTO @strSQL5
	END
	CLOSE curFKs
	DEALLOCATE curFKs
	PRINT '--############# Ended FK index creation statements #############' + CHAR(10)
END
ELSE
BEGIN
	SELECT 'FK_no_Index' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Indexing per Table subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Indexing per Table subsection', 10, 1) WITH NOWAIT

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs3%')
DROP TABLE #tblIxs3
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs3%')
CREATE TABLE #tblIxs3 ([Operation] tinyint, [databaseID] int, [DatabaseName] sysname, [schemaName] VARCHAR(100), [objectName] VARCHAR(200))

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs4%')
DROP TABLE #tblIxs4
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs4%')
CREATE TABLE #tblIxs4 ([databaseID] int, [DatabaseName] sysname, [schemaName] VARCHAR(100), [objectName] VARCHAR(200), [CntCols] int, [CntIxs] int)
	
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs5%')
DROP TABLE #tblIxs5
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs5%')
CREATE TABLE #tblIxs5 ([databaseID] int, [DatabaseName] sysname, [schemaName] VARCHAR(100), [objectName] VARCHAR(200), [indexName] VARCHAR(200), [indexLocation]  VARCHAR(200))

UPDATE #tmpdbs1
SET isdone = 0

WHILE (SELECT COUNT(id) FROM #tmpdbs1 WHERE isdone = 0) > 0
BEGIN
	SELECT TOP 1 @dbname = [dbname], @dbid = [dbid] FROM #tmpdbs1 WHERE isdone = 0
	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT 1 AS [Check], ' + CONVERT(VARCHAR(8), @dbid) + ', ''' + @dbname + ''',	s.name, t.name
FROM sys.indexes AS si (NOLOCK)
INNER JOIN sys.tables AS t (NOLOCK) ON si.[object_id] = t.[object_id]
INNER JOIN sys.schemas AS s (NOLOCK) ON s.[schema_id] = t.[schema_id]
GROUP BY si.[object_id], t.name, s.name
HAVING COUNT(index_id) = 1 AND MAX(index_id) = 0
UNION ALL
SELECT 2 AS [Check], ' + CONVERT(VARCHAR(8), @dbid) + ', ''' + @dbname + ''',	s.name, t.name
FROM sys.indexes AS si (NOLOCK) 
INNER JOIN sys.tables AS t (NOLOCK) ON si.[object_id] = t.[object_id]
INNER JOIN sys.schemas AS s (NOLOCK) ON s.[schema_id] = t.[schema_id]
GROUP BY t.name, s.name
HAVING COUNT(index_id) > 1 AND MIN(index_id) = 0;'
	BEGIN TRY
		INSERT INTO #tblIxs3
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Indexing per Table subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH

	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT ' + CONVERT(VARCHAR(8), @dbid) + ', ''' + @dbname + ''',	s.name, t.name, COUNT(c.column_id), 
(SELECT COUNT(si.index_id) FROM sys.tables AS t2 INNER JOIN sys.indexes AS si ON si.[object_id] = t2.[object_id]
	WHERE si.index_id > 0 AND si.[object_id] = t.[object_id]
	GROUP BY si.[object_id])
FROM sys.tables AS t (NOLOCK)
INNER JOIN sys.columns AS c (NOLOCK) ON t.[object_id] = c.[object_id] 
INNER JOIN sys.schemas AS s (NOLOCK) ON s.[schema_id] = t.[schema_id]
GROUP BY s.name, t.name, t.[object_id];'
	BEGIN TRY
		INSERT INTO #tblIxs4
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Indexing per Table subsection - Error raised in TRY block 2. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH

	SET @sqlcmd = 'USE ' + QUOTENAME(@dbname) + ';
SELECT DISTINCT ' + CONVERT(VARCHAR(8), @dbid) + ', ''' + @dbname + ''', s.name, t.name, i.name, ds.name
FROM sys.tables AS t (NOLOCK)
INNER JOIN sys.indexes AS i (NOLOCK) ON t.[object_id] = i.[object_id] 
INNER JOIN sys.data_spaces AS ds (NOLOCK) ON ds.data_space_id = i.data_space_id
INNER JOIN sys.schemas AS s (NOLOCK) ON s.[schema_id] = t.[schema_id]
WHERE t.[type] = ''U''
	AND i.type IN (1, 2)
	-- Get partitioned tables
	AND t.name IN (SELECT ob.name 
			FROM sys.tables AS ob (NOLOCK)
			INNER JOIN sys.indexes AS ind (NOLOCK) ON ind.[object_id] = ob.[object_id] 
			INNER JOIN sys.data_spaces AS sds (NOLOCK) ON sds.data_space_id = ind.data_space_id
			WHERE sds.[type] = ''PS''
			GROUP BY ob.name)
	AND ds.[type] <> ''PS'';'
	BEGIN TRY
		INSERT INTO #tblIxs5
		EXECUTE sp_executesql @sqlcmd
	END TRY
	BEGIN CATCH
		SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
		SELECT @ErrorMessage = 'Indexing per Table subsection - Error raised in TRY block 3. ' + ERROR_MESSAGE()
		RAISERROR (@ErrorMessage, 16, 1);
	END CATCH
		
	UPDATE #tmpdbs1
	SET isdone = 1
	WHERE dbid = @dbid
END;

IF (SELECT COUNT(*) FROM #tblIxs3 WHERE [Operation] = 1) > 0
BEGIN
	SELECT 'Tables_with_no_Indexes' AS [Check], '[WARNING: Some tables do not have indexes]' AS [Deviation]
	SELECT 'Tables_with_no_Indexes' AS [Check], [DatabaseName], schemaName, [objectName] FROM #tblIxs3 WHERE [Operation] = 1
END
ELSE
BEGIN
	SELECT 'Tables_with_no_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

IF (SELECT COUNT(*) FROM #tblIxs3 WHERE [Operation] = 2) > 0
BEGIN
	SELECT 'Tables_with_no_CL_Index' AS [Check], '[WARNING: Some tables do not have a clustered index, but have non-clustered index(es)]' AS [Deviation]
	SELECT 'Tables_with_no_CL_Index' AS [Check], [DatabaseName], schemaName, [objectName] FROM #tblIxs3 WHERE [Operation] = 2
END
ELSE
BEGIN
	SELECT 'Tables_with_no_CL_Index' AS [Check], '[OK]' AS [Deviation]
END;

IF (SELECT COUNT(*) FROM #tblIxs4 WHERE [CntCols] < [CntIxs]) > 0
BEGIN
	SELECT 'Tables_with_more_Indexes_than_Cols' AS [Check], '[WARNING: Some tables have more indexes than columns]' AS [Deviation]
	SELECT 'Tables_with_more_Indexes_than_Cols' AS [Check], [DatabaseName], schemaName, [objectName], [CntCols] AS [Cnt_Columns], [CntIxs] AS [Cnt_Indexes] FROM #tblIxs4 WHERE [CntCols] < [CntIxs]
END
ELSE
BEGIN
	SELECT 'Tables_with_more_Indexes_than_Cols' AS [Check], '[OK]' AS [Deviation]
END;
	
IF (SELECT COUNT(*) FROM #tblIxs5) > 0
BEGIN
	SELECT 'Tables_with_partition_misaligned_Indexes' AS [Check], '[WARNING: Some partitioned tables have indexes that are not aligned with the partition schema]' AS [Deviation]
	SELECT 'Tables_with_partition_misaligned_Indexes' AS [Check], [DatabaseName], schemaName, [objectName], [indexName], [indexLocation] FROM #tblIxs5
END
ELSE
BEGIN
	SELECT 'Tables_with_partition_misaligned_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Missing Indexes subsection
-- Outputs only potentially most relevant, based in scoring method - use at you own discretion)
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Missing Indexes subsection', 10, 1) WITH NOWAIT
DECLARE @IC VARCHAR(4000), @ICWI VARCHAR(4000), @editionCheck bit

/* Refer to http://msdn.microsoft.com/en-us/library/ms174396.aspx */	
IF (SELECT SERVERPROPERTY('EditionID')) IN (1804890536, 1872460670, 610778273, -2117995310)	
SET @editionCheck = 1 -- supports enterprise only features
ELSE	
SET @editionCheck = 0; -- does not support enterprise only features
	
-- Create the helper functions
EXEC ('USE tempdb; IF EXISTS (SELECT 1 FROM tempdb.sys.objects WHERE name = N''fn_createindex_allcols'') DROP FUNCTION dbo.fn_createindex_allcols')
EXEC ('USE tempdb; EXEC(''
CREATE FUNCTION dbo.fn_createindex_allcols (@ix_handle int)
RETURNS NVARCHAR(max)
AS
BEGIN
	DECLARE @ReturnCols NVARCHAR(max)
	;WITH ColumnToPivot ([data()]) AS ( 
		SELECT CONVERT(VARCHAR(3),ic.column_id) + N'''','''' 
		FROM sys.dm_db_missing_index_details id 
		CROSS APPLY sys.dm_db_missing_index_columns(id.index_handle) ic
		WHERE id.index_handle = @ix_handle 
		ORDER BY ic.column_id ASC
		FOR XML PATH(''''''''), TYPE 
		), 
		XmlRawData (CSVString) AS ( 
			SELECT (SELECT [data()] AS InputData 
			FROM ColumnToPivot AS d FOR XML RAW, TYPE).value(''''/row[1]/InputData[1]'''', ''''NVARCHAR(max)'''') AS CSVCol 
		) 
	SELECT @ReturnCols = CASE WHEN LEN(CSVString) <= 1 THEN NULL ELSE LEFT(CSVString, LEN(CSVString)-1) END
	FROM XmlRawData
	RETURN (@ReturnCols)
END'')
')
EXEC ('USE tempdb; IF EXISTS (SELECT 1 FROM tempdb.sys.objects WHERE name = N''fn_createindex_keycols'') DROP FUNCTION dbo.fn_createindex_keycols')
EXEC ('USE tempdb; EXEC(''
CREATE FUNCTION dbo.fn_createindex_keycols (@ix_handle int)
RETURNS NVARCHAR(max)
AS
BEGIN
	DECLARE @ReturnCols NVARCHAR(max)
	;WITH ColumnToPivot ([data()]) AS ( 
		SELECT CONVERT(VARCHAR(3),ic.column_id) + N'''','''' 
		FROM sys.dm_db_missing_index_details id 
		CROSS APPLY sys.dm_db_missing_index_columns(id.index_handle) ic
		WHERE id.index_handle = @ix_handle
		AND (ic.column_usage = ''''EQUALITY'''' OR ic.column_usage = ''''INEQUALITY'''')
		ORDER BY ic.column_id ASC
		FOR XML PATH(''''''''), TYPE 
		), 
		XmlRawData (CSVString) AS ( 
			SELECT (SELECT [data()] AS InputData 
			FROM ColumnToPivot AS d FOR XML RAW, TYPE).value(''''/row[1]/InputData[1]'''', ''''NVARCHAR(max)'''') AS CSVCol 
		) 
	SELECT @ReturnCols = CASE WHEN LEN(CSVString) <= 1 THEN NULL ELSE LEFT(CSVString, LEN(CSVString)-1) END
	FROM XmlRawData
	RETURN (@ReturnCols)
END'')
')
EXEC ('USE tempdb; IF EXISTS (SELECT 1 FROM tempdb.sys.objects WHERE name = N''fn_createindex_includecols'') DROP FUNCTION dbo.fn_createindex_includecols')
EXEC ('USE tempdb; EXEC(''
CREATE FUNCTION dbo.fn_createindex_includecols (@ix_handle int)
RETURNS NVARCHAR(max)
AS
BEGIN
	DECLARE @ReturnCols NVARCHAR(max)
	;WITH ColumnToPivot ([data()]) AS ( 
		SELECT CONVERT(VARCHAR(3),ic.column_id) + N'''','''' 
		FROM sys.dm_db_missing_index_details id 
		CROSS APPLY sys.dm_db_missing_index_columns(id.index_handle) ic
		WHERE id.index_handle = @ix_handle
		AND ic.column_usage = ''''INCLUDE''''
		ORDER BY ic.column_id ASC
		FOR XML PATH(''''''''), TYPE 
		), 
		XmlRawData (CSVString) AS ( 
			SELECT (SELECT [data()] AS InputData 
			FROM ColumnToPivot AS d FOR XML RAW, TYPE).value(''''/row[1]/InputData[1]'''', ''''NVARCHAR(max)'''') AS CSVCol 
		) 
	SELECT @ReturnCols = CASE WHEN LEN(CSVString) <= 1 THEN NULL ELSE LEFT(CSVString, LEN(CSVString)-1) END
	FROM XmlRawData
	RETURN (@ReturnCols)
END'')
')

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects WHERE [name] LIKE '#IndexCreation%')
DROP TABLE #IndexCreation
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects WHERE [name] LIKE '#IndexCreation%')
CREATE TABLE #IndexCreation (
	[database_id] int,
	DBName VARCHAR(255),
	[Table] VARCHAR(255),
	[ix_handle] int,
	[User_Hits_on_Missing_Index] int,
	[Estimated_Improvement_Percent] DECIMAL(5,2),
	[Avg_Total_User_Cost] int,
	[Unique_Compiles] int,
	[Score] NUMERIC(19,3),
	[KeyCols] VARCHAR(1000),
	[IncludedCols] VARCHAR(4000),
	[Ix_Name] VARCHAR(255),
	[AllCols] NVARCHAR(max),
	[KeyColsOrdered] NVARCHAR(max),
	[IncludedColsOrdered] NVARCHAR(max)
	)

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects WHERE [name] LIKE '#IndexRedundant%')
DROP TABLE #IndexRedundant
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects WHERE [name] LIKE '#IndexRedundant%')
CREATE TABLE #IndexRedundant (
	DBName VARCHAR(255),
	[Table] VARCHAR(255),
	[Ix_Name] VARCHAR(255),
	[ix_handle] int,
	[KeyCols] VARCHAR(1000),
	[IncludedCols] VARCHAR(4000),
	[Redundant_With] VARCHAR(255)
	)

INSERT INTO #IndexCreation
SELECT i.database_id,
	m.[name],
	RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3)) AS [Table],
	i.index_handle AS [ix_handle],
	[User_Hits_on_Missing_Index] = (s.user_seeks + s.user_scans),
	s.avg_user_impact, -- Query cost would reduce by this amount in percentage, on average.
	s.avg_total_user_cost, -- Average cost of the user queries that could be reduced by the index in the group.
	s.unique_compiles, -- Number of compilations and recompilations that would benefit from this missing index group.
	(CONVERT(NUMERIC(19,3), s.user_seeks) + CONVERT(NUMERIC(19,3), s.user_scans)) 
		* CONVERT(NUMERIC(19,3), s.avg_total_user_cost) 
		* CONVERT(NUMERIC(19,3), s.avg_user_impact) AS Score, -- The higher the score, higher is the anticipated improvement for user queries.
	CASE WHEN (i.equality_columns IS NOT NULL AND i.inequality_columns IS NULL) THEN i.equality_columns
			WHEN (i.equality_columns IS NULL AND i.inequality_columns IS NOT NULL) THEN i.inequality_columns
			ELSE i.equality_columns + ',' + i.inequality_columns END AS [KeyCols],
	i.included_columns AS [IncludedCols],
	'IX_' + LEFT(RIGHT(RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3)), LEN(RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3))) - (CHARINDEX('.', RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3)), 1)) - 1),
		LEN(RIGHT(RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3)), LEN(RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3))) - (CHARINDEX('.', RIGHT(i.[statement], LEN(i.[statement]) - (LEN(m.[name]) + 3)), 1)) - 1)) - 1) + '_' + CAST(i.index_handle AS NVARCHAR) AS [Ix_Name],
	tempdb.dbo.fn_createindex_allcols(i.index_handle), 
	tempdb.dbo.fn_createindex_keycols(i.index_handle),
	tempdb.dbo.fn_createindex_includecols(i.index_handle)
FROM sys.dm_db_missing_index_details i
INNER JOIN master.sys.databases m ON i.database_id = m.database_id
INNER JOIN sys.dm_db_missing_index_groups g ON i.index_handle = g.index_handle
INNER JOIN sys.dm_db_missing_index_group_stats s ON s.group_handle = g.index_group_handle
WHERE i.database_id > 4
	
INSERT INTO #IndexRedundant
SELECT I.DBName, I.[Table], I.[Ix_Name], i.[ix_handle], I.[KeyCols], I.[IncludedCols], I2.[Ix_Name]
FROM #IndexCreation I INNER JOIN #IndexCreation I2
ON I.[database_id] = I2.[database_id] AND I.[Table] = I2.[Table] AND I.[Ix_Name] <> I2.[Ix_Name]
	AND (((I.KeyColsOrdered <> I2.KeyColsOrdered OR I.[IncludedColsOrdered] <> I2.[IncludedColsOrdered])
		AND ((CASE WHEN I.[IncludedColsOrdered] IS NULL THEN I.KeyColsOrdered ELSE I.KeyColsOrdered + ',' + I.[IncludedColsOrdered] END) = (CASE WHEN I2.[IncludedColsOrdered] IS NULL THEN I2.KeyColsOrdered ELSE I2.KeyColsOrdered + ',' + I2.[IncludedColsOrdered] END)
			OR I.[AllCols] = I2.[AllCols]))
	OR (I.KeyColsOrdered <> I2.KeyColsOrdered AND I.[IncludedColsOrdered] = I2.[IncludedColsOrdered])
	OR (I.KeyColsOrdered = I2.KeyColsOrdered AND I.[IncludedColsOrdered] <> I2.[IncludedColsOrdered]))
WHERE I.[Score] >= 100000
	AND I2.[Score] >= 100000
GROUP BY I.DBName, I.[Table], I.[Ix_Name], I.[ix_handle], I.[KeyCols], I.[IncludedCols], I2.[Ix_Name]
ORDER BY I.DBName, I.[Table], I.[Ix_Name]

IF (SELECT COUNT(*) FROM #IndexCreation) > 0
BEGIN
	SELECT 'Missing_Indexes' AS [Check], '[INFORMATION: Potentially missing indexes were found. It may be important to revise these]' AS [Deviation]
	SELECT 'Missing_Indexes' AS [Information], IC.DBName AS [Database_Name], IC.[Table] AS [Table_Name] ,CONVERT(bigint,[Score]) AS [Score],[User_Hits_on_Missing_Index], 
		[Estimated_Improvement_Percent], [Avg_Total_User_Cost], [Unique_Compiles], IC.[KeyCols], IC.[IncludedCols], IC.[Ix_Name] AS [Index_Name],
		CASE WHEN IR.[ix_handle] IS NOT NULL THEN 1 ELSE 0 END AS [Possible_Redundant], IR.[Redundant_With]
	FROM #IndexCreation IC
	LEFT JOIN #IndexRedundant IR ON IC.DBName = IR.DBName AND IC.[Table] = IR.[Table] AND IC.[ix_handle] = IR.[ix_handle]
	WHERE [Score] >= 100000
	ORDER BY IC.DBName, IC.[Score] DESC, IC.[User_Hits_on_Missing_Index], IC.[Estimated_Improvement_Percent];		
		
	SELECT 'Missing_Indexes' AS [Check], 'Possibly_redundant_IXs_in_list' AS Comments, I.DBName AS [Database_Name], I.[Table] AS [Table_Name], 
		I.[Ix_Name] AS [Index_Name], I.[KeyCols], I.[IncludedCols]
	FROM #IndexRedundant I
	ORDER BY I.DBName, I.[Table], I.[Ix_Name]

	PRINT '** Generated on ' + CONVERT (VARCHAR, GETDATE()) + ' in ' + @@SERVERNAME + ' */' + CHAR(10)
	PRINT '--############# Indexes creation statements #############' + CHAR(10)
	DECLARE cIC CURSOR FAST_FORWARD FOR
	SELECT '-- User Hits on Missing Index ' + IC.[Ix_Name] + ': ' + CONVERT(VARCHAR(20),IC.[User_Hits_on_Missing_Index]) + CHAR(10) +
		'-- Estimated Improvement Percent: ' + CONVERT(VARCHAR(6),IC.[Estimated_Improvement_Percent]) + CHAR(10) +
		'-- Average Total User Cost: ' + CONVERT(VARCHAR(50),IC.[Avg_Total_User_Cost]) + CHAR(10) +
		'-- Unique Compiles: ' + CONVERT(VARCHAR(50),IC.[Unique_Compiles]) + CHAR(10) +
		'-- Score: ' + CONVERT(VARCHAR(20),CONVERT(bigint,IC.[Score])) + 
		CASE WHEN IR.[Redundant_With] IS NOT NULL THEN CHAR(10) + '-- Redundant with missing index: ' + [Redundant_With] ELSE '' END + CHAR(10) +
		'USE ' + QUOTENAME(IC.DBName) + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sysindexes WHERE name = N''' +
		IC.[Ix_Name] + ''') DROP INDEX ' + IC.[Table] + '.' +
		IC.[Ix_Name] + ';' + CHAR(10) + 'GO' + CHAR(10) + 'CREATE INDEX ' +
		IC.[Ix_Name] + ' ON ' + IC.[Table] + ' (' + IC.[KeyCols] + CASE WHEN @editionCheck = 1 THEN ') WITH (ONLINE = ON);' ELSE ');' END + CHAR(10) + 'GO' + CHAR(10)
	FROM #IndexCreation IC
	LEFT JOIN #IndexRedundant IR ON IC.DBName = IR.DBName AND IC.[Table] = IR.[Table] AND IC.[ix_handle] = IR.[ix_handle]
	WHERE IC.[IncludedCols] IS NULL AND IC.[Score] >= 100000
	ORDER BY IC.DBName, IC.[Table], IC.[Ix_Name]
	OPEN cIC
	FETCH NEXT FROM cIC INTO @IC
	WHILE @@FETCH_STATUS = 0
		BEGIN
			PRINT @IC
			FETCH NEXT FROM cIC INTO @IC
		END
	CLOSE cIC
	DEALLOCATE cIC

	PRINT '--############# Covering indexes creation statements #############' + CHAR(10)
	DECLARE cICWI CURSOR FAST_FORWARD FOR
	SELECT '-- User Hits on Missing Index ' + IC.[Ix_Name] + ': ' + CONVERT(VARCHAR(20),IC.[User_Hits_on_Missing_Index]) + CHAR(10) +
		'-- Estimated Improvement Percent: ' + CONVERT(VARCHAR(6),IC.[Estimated_Improvement_Percent]) + CHAR(10) +
		'-- Average Total User Cost: ' + CONVERT(VARCHAR(50),IC.[Avg_Total_User_Cost]) + CHAR(10) +
		'-- Unique Compiles: ' + CONVERT(VARCHAR(50),IC.[Unique_Compiles]) + CHAR(10) +
		'-- Score: ' + CONVERT(VARCHAR(20),CONVERT(bigint,IC.[Score])) + 
		CASE WHEN IR.[Redundant_With] IS NOT NULL THEN CHAR(10) + '-- Redundant with missing index: ' + [Redundant_With] ELSE '' END + CHAR(10) +
		'USE ' + QUOTENAME(IC.DBName) + CHAR(10) + 'GO' + CHAR(10) + 'IF EXISTS (SELECT name FROM sysindexes WHERE name = N''' +
		IC.[Ix_Name] + ''') DROP INDEX ' + IC.[Table] + '.' +
		IC.[Ix_Name] + ';' + CHAR(10) + 'GO' + CHAR(10) + 'CREATE INDEX ' +
		IC.[Ix_Name] + ' ON ' + IC.[Table] + ' (' + IC.[KeyCols] + CASE WHEN @editionCheck = 1 THEN ') WITH (ONLINE = ON);' ELSE ');' END + CHAR(10) + 'GO' + CHAR(10)
	FROM #IndexCreation IC
	LEFT JOIN #IndexRedundant IR ON IC.DBName = IR.DBName AND IC.[Table] = IR.[Table] AND IC.[ix_handle] = IR.[ix_handle]
	WHERE IC.[IncludedCols] IS NOT NULL AND IC.[Score] >= 100000
	ORDER BY IC.DBName, IC.[Table], IC.[Ix_Name]
	OPEN cICWI
	FETCH NEXT FROM cICWI INTO @ICWI
	WHILE @@FETCH_STATUS = 0
		BEGIN
			PRINT @ICWI
			FETCH NEXT FROM cICWI INTO @ICWI
		END
	CLOSE cICWI
	DEALLOCATE cICWI
		
	PRINT '--############# Ended missing indexes creation statements #############' + CHAR(10)
END
ELSE
BEGIN
	SELECT 'Missing_Indexes' AS [Check], '[OK]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- DBCC CHECKDB, Direct Catalog Updates and Data Purity subsection
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting DBCC CHECKDB, Direct Catalog Updates and Data Purity subsection', 10, 1) WITH NOWAIT
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#output_dbinfo%')
DROP TABLE #output_dbinfo
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#output_dbinfo%')
CREATE TABLE #output_dbinfo (ParentObject VARCHAR(255), [Object] VARCHAR(255), Field VARCHAR(255), [value] VARCHAR(255))
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbinfo%')
DROP TABLE #dbinfo
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbinfo%')
CREATE TABLE #dbinfo (rowid int IDENTITY(1,1) PRIMARY KEY CLUSTERED, dbname NVARCHAR(255), lst_known_checkdb DATETIME NULL, updSysCatalog DATETIME NULL, dbi_createVersion int NULL, dbi_dbccFlags int NULL) 

IF (ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1)
BEGIN
	--DECLARE @dbname NVARCHAR(255);
	DECLARE @dbcc bit, @catupd bit, @purity bit;
	DECLARE curDBs CURSOR FAST_FORWARD FOR SELECT name FROM master.sys.databases (NOLOCK) WHERE is_read_only = 0 AND state = 0
	OPEN curDBs
	FETCH NEXT FROM curDBs INTO @dbname
	WHILE (@@FETCH_STATUS = 0)
	BEGIN
		SET @dbname = RTRIM(LTRIM(@dbname))
		INSERT INTO #output_dbinfo
		EXEC('DBCC DBINFO(''' + @dbname + ''') WITH TABLERESULTS, NO_INFOMSGS')
		INSERT INTO #dbinfo (dbname, lst_known_checkdb)
		SELECT @dbname, [value] FROM #output_dbinfo WHERE Field LIKE 'dbi_dbccLastKnownGood%';
		UPDATE #dbinfo
		SET #dbinfo.updSysCatalog = #output_dbinfo.[value]
		FROM #output_dbinfo 
		WHERE #dbinfo.dbname = @dbname AND #output_dbinfo.Field LIKE 'dbi_updSysCatalog%';
		UPDATE #dbinfo
		SET #dbinfo.dbi_dbccFlags = #output_dbinfo.[value]
		FROM #output_dbinfo 
		WHERE #dbinfo.dbname = @dbname AND #output_dbinfo.Field LIKE 'dbi_createVersion%';
		UPDATE #dbinfo
		SET #dbinfo.dbi_dbccFlags = #output_dbinfo.[value]
		FROM #output_dbinfo 
		WHERE #dbinfo.dbname = @dbname AND #output_dbinfo.Field LIKE 'dbi_dbccFlags%';
		TRUNCATE TABLE #output_dbinfo;
		FETCH NEXT FROM curDBs INTO @dbname
	END
	CLOSE curDBs
	DEALLOCATE curDBs;

	;WITH cte_dbcc (name, lst_known_checkdb) AS (SELECT sd.name, tmpdbi.lst_known_checkdb 
		FROM master.sys.databases sd (NOLOCK) LEFT JOIN #dbinfo tmpdbi ON sd.name = tmpdbi.dbname
		WHERE sd.database_id <> 2)
	SELECT @dbcc = CASE WHEN COUNT(name) > 0 THEN 1 ELSE 0 END 
	FROM cte_dbcc WHERE DATEDIFF(dd, lst_known_checkdb, GETDATE()) > 7 OR lst_known_checkdb IS NULL;

	;WITH cte_catupd (name, updSysCatalog) AS (SELECT sd.name, tmpdbi.updSysCatalog 
		FROM master.sys.databases sd (NOLOCK) LEFT JOIN #dbinfo tmpdbi ON sd.name = tmpdbi.dbname
		WHERE sd.database_id <> 2)
	SELECT @catupd = CASE WHEN COUNT(name) > 0 THEN 1 ELSE 0 END 
	FROM cte_catupd WHERE updSysCatalog > '1900-01-01 00:00:00.000';

	;WITH cte_purity (name, dbi_createVersion, dbi_dbccFlags) AS (SELECT sd.name, tmpdbi.dbi_createVersion, tmpdbi.dbi_dbccFlags 
		FROM master.sys.databases sd (NOLOCK) LEFT JOIN #dbinfo tmpdbi ON sd.name = tmpdbi.dbname
		WHERE sd.database_id > 4)
	SELECT @purity = CASE WHEN COUNT(name) > 0 THEN 1 ELSE 0 END 
	FROM cte_purity WHERE dbi_createVersion <= 611 AND dbi_dbccFlags = 0; -- <= SQL Server 2005

	IF @dbcc = 1
	BEGIN
		SELECT 'DBCC_CHECKDB' AS [Check], '[WARNING: database integrity checks have not been executed for over 7 days on some or all databases. It is recommended to run DBCC CHECKDB on these databases as soon as possible]' AS [Deviation]
		SELECT 'DBCC_CHECKDB' AS [Information], [name] AS [Database_Name], MAX(lst_known_checkdb) AS Last_Known_CHECKDB
		FROM master.sys.databases (NOLOCK) LEFT JOIN #dbinfo tmpdbi ON name = tmpdbi.dbname
		WHERE database_id <> 2
		GROUP BY [name]
		HAVING DATEDIFF(dd, MAX(lst_known_checkdb), GETDATE()) > 7 OR MAX(lst_known_checkdb) IS NULL
		ORDER BY [name]
	END
	ELSE
	BEGIN
		SELECT 'DBCC_CHECKDB' AS [Check], '[OK]' AS [Deviation]
	END;

	IF @catupd = 1
	BEGIN
		SELECT 'Direct_Catalog_Updates' AS [Check], '[WARNING: Microsoft does not support direct catalog updates to databases.]' AS [Deviation]
		SELECT 'Direct_Catalog_Updates' AS [Information], [name] AS [Database_Name], MAX(updSysCatalog) AS Last_Direct_Catalog_Update
		FROM master.sys.databases (NOLOCK) LEFT JOIN #dbinfo tmpdbi ON name = tmpdbi.dbname
		WHERE database_id <> 2 
		GROUP BY [name]
		HAVING (MAX(updSysCatalog) > '1900-01-01 00:00:00.000')
		ORDER BY [name]
	END
	ELSE
	BEGIN
		SELECT 'Direct_Catalog_Updates' AS [Check], '[OK]' AS [Deviation]
	END;
		
	-- http://support.microsoft.com/kb/923247/en-us
	-- http://www.sqlskills.com/blogs/paul/checkdb-from-every-angle-how-to-tell-if-data-purity-checks-will-be-run
	IF @purity = 1
	BEGIN
		SELECT 'Databases_need_data_purity_check' AS [Check], '[WARNING: Databases were found that need to run data purity checks.]' AS [Deviation]
		SELECT 'Databases_need_data_purity_check' AS [Information], [name] AS [Database_Name], dbi_dbccFlags AS Needs_Data_Purity_Checks
		FROM master.sys.databases (NOLOCK) LEFT JOIN #dbinfo tmpdbi ON name = tmpdbi.dbname
		WHERE database_id > 4 AND dbi_createVersion <= 611 AND dbi_dbccFlags = 0
		ORDER BY [name]
	END
	ELSE
	BEGIN
		SELECT 'Databases_need_data_purity_check' AS [Check], '[OK]' AS [Deviation]
	END;
END
ELSE
BEGIN
	RAISERROR('[WARNING: Only a sysadmin can run the "DBCC CHECKDB, Direct Catalog Updates and Data Purity" checks. Bypassing check]', 16, 1, N'sysadmin')
	--RETURN
END;

--------------------------------------------------------------------------------------------------------------------------------
-- AlwaysOn/Mirroring automatic page repair subsection
-- Refer to "Automatic Page Repair" BOL entry for more information (http://msdn.microsoft.com/en-us/library/bb677167.aspx) 
--------------------------------------------------------------------------------------------------------------------------------
IF @sqlmajorver > 9
BEGIN
	RAISERROR (N'|-Starting AlwaysOn/Mirroring automatic page repair subsection', 10, 1) WITH NOWAIT
		
	IF @sqlmajorver > 10
	BEGIN
		DECLARE @HadrRep int--, @sqlcmd NVARCHAR(4000), @params NVARCHAR(500)
		SET @sqlcmd = N'SELECT @HadrRepOUT = COUNT(*) FROM sys.dm_hadr_auto_page_repair';
		SET @params = N'@HadrRepOUT int OUTPUT';
		EXECUTE sp_executesql @sqlcmd, @params, @HadrRepOUT=@HadrRep OUTPUT;
	END
	ELSE
	BEGIN
		SET @HadrRep = 0
	END;
		
	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#pagerepair%')
	DROP TABLE #pagerepair
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#pagerepair%')
	CREATE TABLE #pagerepair (rowid int IDENTITY(1,1) PRIMARY KEY CLUSTERED, dbname NVARCHAR(255), [file_id] int NULL, [page_id] bigint NULL, error_type smallint NULL, page_status tinyint NULL, lst_modification_time DATETIME NULL, Repair_Source VARCHAR(20) NULL) 

	IF (SELECT COUNT(*) FROM sys.dm_db_mirroring_auto_page_repair (NOLOCK)) > 0
	BEGIN
		INSERT INTO #pagerepair
		SELECT DB_NAME(database_id) AS [Database_Name], [file_id], [page_id], [error_type], page_status, MAX(modification_time), 'Mirroring' AS [Repair_Source]
		FROM sys.dm_db_mirroring_auto_page_repair (NOLOCK)
		GROUP BY database_id, [file_id], [page_id], [error_type], page_status
	END
		
	IF @HadrRep > 0
	BEGIN
		INSERT INTO #pagerepair
		EXEC ('SELECT DB_NAME(database_id) AS [Database_Name], [file_id], [page_id], [error_type], page_status, MAX(modification_time), ''HADR'' AS [Repair_Source] FROM sys.dm_hadr_auto_page_repair GROUP BY database_id, [file_id], [page_id], [error_type], page_status ORDER BY DB_NAME(database_id), MAX(modification_time) DESC, [file_id], [page_id]')
	END		
		
	IF (SELECT COUNT(*) FROM sys.dm_db_mirroring_auto_page_repair (NOLOCK)) > 0
		OR @HadrRep > 0
	BEGIN
		SELECT 'Auto_Page_repairs' AS [Check], '[WARNING: Page repairs have been found. Check for suspect pages]' AS [Deviation]
		SELECT 'Auto_Page_repairs' AS [Information], dbname AS [Database_Name],
			[file_id] AS [File_ID],
			[page_id] AS [Page_ID],
			CASE [error_type]
				WHEN -1 THEN 'Error 823'
				WHEN 1 THEN 'Unspecified Error 824'
				WHEN 2 THEN 'Bad Checksum'
				WHEN 3 THEN 'Torn Page'
				ELSE NULL
			END AS [Error_Type],
			CASE page_status 
				WHEN 2 THEN 'Queued for request from partner'
				WHEN 3 THEN 'Request sent to partner'
				WHEN 4 THEN 'Queued for automatic page repair' 
				WHEN 5 THEN 'Automatic page repair succeeded'
				WHEN 6 THEN 'Irreparable'
			END AS [Page_Status],
			lst_modification_time AS [Last_Modification_Time], [Repair_Source]
		FROM #pagerepair
	END
	ELSE
	BEGIN
		SELECT 'Auto_Page_repairs' AS [Check], '[None]' AS [Deviation], '' AS [Source] 
	END
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Suspect pages subsection
-- Refer to "Manage the suspect_pages Table" BOL entry for more information (http://msdn.microsoft.com/en-us/library/ms191301.aspx) 
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Suspect pages subsection', 10, 1) WITH NOWAIT
IF (SELECT COUNT(*) FROM msdb.dbo.suspect_pages WHERE (event_type = 1 OR event_type = 2 OR event_type = 3)) > 0
BEGIN
	SELECT 'Suspect_Pages' AS [Check], '[WARNING: Suspect pages have been found. Run DBCC CHECKDB to verify affected databases]' AS [Deviation]
	SELECT 'Suspect_Pages' AS [Information], DB_NAME(database_id) AS [Database_Name],
		[file_id] AS [File_ID],
		[page_id] AS [Page_ID],
		CASE event_type
			WHEN 1 THEN 'Error 823 or unspecified Error 824'
			WHEN 2 THEN 'Bad Checksum'
			WHEN 3 THEN 'Torn Page'
			ELSE NULL
		END AS [Event_Type],
		error_count AS [Error_Count],
		last_update_date AS [Last_Update_Date]
	FROM msdb.dbo.suspect_pages (NOLOCK)
	WHERE (event_type = 1 OR event_type = 2 OR event_type = 3) 
	ORDER BY DB_NAME(database_id), last_update_date DESC, [file_id], [page_id]
END
ELSE
BEGIN
	SELECT 'Suspect_Pages' AS [Check], '[None]' AS [Deviation]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- I/O stall in database files over 50% of sampled time or I/O latencies over 20ms subsection
-- io_stall refers to user processes waited for I/O. This number can be much greater than the sample_ms.
-- Might indicate that your I/O has insuficient service capabilities (HBA queue depths, reduced throughput, etc). 
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting I/O Stall subsection', 10, 1) WITH NOWAIT
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIOStall%')
DROP TABLE #tblIOStall
IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIOStall%')
CREATE TABLE #tblIOStall (database_id int, [file_id] int, [DBName] sysname, [logical_file_name] NVARCHAR(255), [type_desc] NVARCHAR(60),
	[physical_name] NVARCHAR(260), size_on_disk_Mbytes int, num_of_reads bigint, num_of_writes bigint, num_of_Mbytes_read bigint, num_of_Mbytes_written bigint,
	io_stall_min int, io_stall_read_min int, io_stall_write_min int, avg_read_latency_ms int, avg_write_latency_ms int, io_stall_read_pct int, io_stall_write_pct int, sampled_HH int, 
	io_stall_pct_of_overall_sample int, 		
	CONSTRAINT PK_IOStall PRIMARY KEY CLUSTERED(database_id, [file_id]))

INSERT INTO #tblIOStall
SELECT f.database_id, f.[file_id], DB_NAME(f.database_id), f.name AS logical_file_name, f.type_desc, 
	CAST (CASE 
		-- Handle UNC paths (e.g. '\\fileserver\readonlydbs\dept_dw.ndf')
		WHEN LEFT (LTRIM (f.physical_name), 2) = '\\' 
			THEN LEFT (LTRIM (f.physical_name),CHARINDEX('\',LTRIM(f.physical_name),CHARINDEX('\',LTRIM(f.physical_name), 3) + 1) - 1)
			-- Handle local paths (e.g. 'C:\Program Files\...\master.mdf') 
			WHEN CHARINDEX('\', LTRIM(f.physical_name), 3) > 0 
			THEN UPPER(LEFT(LTRIM(f.physical_name), CHARINDEX ('\', LTRIM(f.physical_name), 3) - 1))
		ELSE f.physical_name
	END AS NVARCHAR(255)) AS logical_disk,
	fs.size_on_disk_bytes/1024/1024 AS size_on_disk_Mbytes,
	fs.num_of_reads, fs.num_of_writes,
	fs.num_of_bytes_read/1024/1024 AS num_of_Mbytes_read,
	fs.num_of_bytes_written/1024/1024 AS num_of_Mbytes_written,
	fs.io_stall/1000/60 AS io_stall_min, 
	fs.io_stall_read_ms/1000/60 AS io_stall_read_min, 
	fs.io_stall_write_ms/1000/60 AS io_stall_write_min,
	(fs.io_stall_read_ms / (1.0 + fs.num_of_reads)) AS avg_read_latency_ms,
	(fs.io_stall_write_ms / (1.0 + fs.num_of_writes)) AS avg_write_latency_ms,
	((fs.io_stall_read_ms/1000/60)*100)/(CASE WHEN fs.io_stall/1000/60 = 0 THEN 1 ELSE fs.io_stall/1000/60 END) AS io_stall_read_pct, 
	((fs.io_stall_write_ms/1000/60)*100)/(CASE WHEN fs.io_stall/1000/60 = 0 THEN 1 ELSE fs.io_stall/1000/60 END) AS io_stall_write_pct,
	ABS((sample_ms/1000)/60/60) AS 'sample_HH', 
	((fs.io_stall/1000/60)*100)/(ABS((sample_ms/1000)/60))AS 'io_stall_pct_of_overall_sample'
FROM sys.dm_io_virtual_file_stats (default, default) AS fs
INNER JOIN sys.master_files AS f ON fs.database_id = f.database_id AND fs.[file_id] = f.[file_id]
		
IF (SELECT COUNT([logical_file_name]) FROM #tblIOStall WHERE io_stall_pct_of_overall_sample > 50) > 0
	OR (SELECT COUNT([logical_file_name]) FROM #tblIOStall WHERE avg_read_latency_ms >= 20) > 0
	OR (SELECT COUNT([logical_file_name]) FROM #tblIOStall WHERE avg_write_latency_ms >= 20) > 0
BEGIN
	SELECT 'Stalled_IO' AS [Check], '[WARNING: Some database files have latencies >= 20ms or stall I/O exceeding 50 pct of sampled time. Review I/O related performance counters and storage-related configurations.]' AS [Deviation]
	SELECT 'Stalled_IO' AS [Information], [DBName] AS [Database_Name], [logical_file_name], [type_desc], avg_read_latency_ms, avg_write_latency_ms, 
	io_stall_read_pct, io_stall_write_pct, sampled_HH, io_stall_pct_of_overall_sample, [physical_name], size_on_disk_Mbytes, num_of_reads AS physical_reads, 
	num_of_writes AS physical_writes, num_of_Mbytes_read, num_of_Mbytes_written, io_stall_min, io_stall_read_min, io_stall_write_min
	FROM #tblIOStall
	ORDER BY io_stall_pct_of_overall_sample DESC, avg_write_latency_ms DESC, avg_read_latency_ms DESC, [DBName], [type_desc], [logical_file_name]
END
ELSE
BEGIN
	SELECT 'Stalled_IO' AS [Check], '[OK]' AS [Deviation]
	SELECT 'Stalled_IO' AS [Information], [DBName] AS [Database_Name], [logical_file_name], [type_desc], avg_read_latency_ms, avg_write_latency_ms, 
	io_stall_read_pct, io_stall_write_pct, sampled_HH, io_stall_pct_of_overall_sample, [physical_name], size_on_disk_Mbytes, num_of_reads AS physical_reads, 
	num_of_writes AS physical_writes, num_of_Mbytes_read, num_of_Mbytes_written, io_stall_min, io_stall_read_min, io_stall_write_min
	FROM #tblIOStall
	ORDER BY [DBName], [type_desc], [logical_file_name]
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Errorlog based checks subsection
-- Because it is a string based search, add other search conditions as deemed fit.
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'|-Starting Errorlog based checks subsection', 10, 1) WITH NOWAIT
--DECLARE @lognumber int, @logcount int
DECLARE @langid smallint
SELECT @langid = lcid FROM sys.syslanguages WHERE name = @@LANGUAGE

IF ISNULL(IS_SRVROLEMEMBER(N'sysadmin'), 0) = 1 -- Is sysadmin
	OR ISNULL(IS_SRVROLEMEMBER(N'securityadmin'), 0) = 1 -- Is securityadmin
	OR ((SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'sp_readerrorlog') > 0
		AND (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_readerrorlog') > 0
		AND (SELECT COUNT([name]) FROM @permstbl WHERE [name] = 'xp_enumerrorlogs') > 0)
BEGIN
	SET @lognumber = 0 

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbcc%')
	DROP TABLE #dbcc
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbcc%')
	CREATE TABLE #dbcc (rowid int IDENTITY(1,1) PRIMARY KEY, logid int NULL, logdate DATETIME, spid VARCHAR(50), logmsg VARCHAR(4000)) 
	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbcc%')
	CREATE INDEX [dbcc_logmsg] ON dbo.[#dbcc](logid) 

	IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#avail_logs%')
	DROP TABLE #avail_logs
	IF NOT EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#avail_logs%')
	CREATE TABLE #avail_logs (lognum int, logdate DATETIME, logsize int) 

	-- Get the number of available logs 
	INSERT INTO #avail_logs 
	EXEC xp_enumerrorlogs 

	SELECT @logcount = MAX(lognum) FROM #avail_logs 

	WHILE @lognumber < @logcount 
	BEGIN
		-- Cycle thru sql error logs
		SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''15 seconds'''
		BEGIN TRY
			INSERT INTO #dbcc (logdate, spid, logmsg) 
			EXECUTE (@sqlcmd);
			UPDATE #dbcc SET logid = @lognumber WHERE logid IS NULL;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 1. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''deadlock'''
		BEGIN TRY
			INSERT INTO #dbcc (logdate, spid, logmsg) 
			EXECUTE (@sqlcmd);
			UPDATE #dbcc SET logid = @lognumber WHERE logid IS NULL;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 2. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''stack dump'''
		BEGIN TRY
			INSERT INTO #dbcc (logdate, spid, logmsg) 
			EXECUTE (@sqlcmd);
			UPDATE #dbcc SET logid = @lognumber WHERE logid IS NULL;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 3. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''Error:'''
		BEGIN TRY
			INSERT INTO #dbcc (logdate, spid, logmsg) 
			EXECUTE (@sqlcmd);
			UPDATE #dbcc SET logid = @lognumber WHERE logid IS NULL;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 4. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''A significant part of sql server process memory has been paged out'''
		BEGIN TRY
			INSERT INTO #dbcc (logdate, spid, logmsg) 
			EXECUTE (@sqlcmd);
			UPDATE #dbcc SET logid = @lognumber WHERE logid IS NULL;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 5. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		SELECT @sqlcmd = 'EXEC master..sp_readerrorlog ' + CONVERT(VARCHAR(3),@lognumber) + ', 1, ''cachestore flush'''
		BEGIN TRY
			INSERT INTO #dbcc (logdate, spid, logmsg) 
			EXECUTE (@sqlcmd);
			UPDATE #dbcc SET logid = @lognumber WHERE logid IS NULL;
		END TRY
		BEGIN CATCH
			SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
			SELECT @ErrorMessage = 'Errorlog based subsection - Error raised in TRY block 6. ' + ERROR_MESSAGE()
			RAISERROR (@ErrorMessage, 16, 1);
		END CATCH
		-- Next log 
		--SET @lognumber = @lognumber + 1 
		SELECT @lognumber = MIN(lognum) FROM #avail_logs WHERE lognum > @lognumber
	END 

	IF (SELECT COUNT([rowid]) FROM #dbcc) > 0
	BEGIN
		SELECT 'Errorlog' AS [Check], '[WARNING: Errorlog contains important messages.]' AS [Deviation];

		;WITH cte_dbcc (err, errcnt, logdate, logmsg) 
			AS (SELECT CASE WHEN logmsg LIKE 'Error: %' THEN RIGHT(LEFT(#dbcc.logmsg, CHARINDEX(',', #dbcc.logmsg)-1), CHARINDEX(',', #dbcc.logmsg)-8) 
					WHEN logmsg LIKE 'SQL Server has encountered % longer than 15 seconds %' THEN CONVERT(CHAR(3),833)
					WHEN logmsg LIKE 'A significant part of sql server process memory has been paged out%' THEN CONVERT(CHAR(5),17890)
					ELSE '' END AS err,
				COUNT(logmsg) AS errcnt, 
				logdate,
				CASE WHEN logmsg LIKE 'SQL Server has encountered % longer than 15 seconds %' THEN 'SQL Server has encountered XXX occurrence(s) of IO requests taking longer than 15 seconds to complete on file YYY'
					WHEN logmsg LIKE 'A significant part of sql server process memory has been paged out%' THEN 'A significant part of sql server process memory has been paged out.'
					ELSE logmsg END AS logmsg
				FROM #dbcc
				GROUP BY logmsg, logdate
				)	
		SELECT 'Errorlog_Summary' AS [Information], 
			err AS [Error_Number],
			SUM(errcnt) AS Error_Count, 
			MIN(logdate) AS [First_Logged_Date], 
			MAX(logdate) AS [Last_Logged_Date],
			logmsg AS [Logged_Message],
			CASE WHEN logmsg LIKE 'Error: 825%' THEN 'IO transient failure. Possible corruption'
				WHEN logmsg LIKE 'Error: 833%' OR logmsg LIKE 'SQL Server has encountered % longer than 15 seconds %' THEN 'Long IO detected: http://support.microsoft.com/kb/897284'
				WHEN logmsg LIKE 'Error: 855%' OR logmsg LIKE 'Error: 856%' THEN 'Hardware memory corruption'
				WHEN logmsg LIKE 'Error: 3452%' THEN 'Metadata inconsistency in DB. Run DBCC CHECKIDENT'
				WHEN logmsg LIKE 'Error: 3619%' THEN 'Chkpoint failed. No Log space available'
				WHEN logmsg LIKE 'Error: 9002%' THEN 'No Log space available'
				WHEN logmsg LIKE 'Error: 17204%' OR logmsg LIKE 'Error: 17207%' THEN 'Error opening file during startup process'
				WHEN logmsg LIKE 'Error: 17179%' THEN 'No AWE - LPIM related'
				WHEN logmsg LIKE 'Error: 17890%' THEN 'sqlservr process paged out'
				WHEN logmsg LIKE 'Error: 2508%' THEN 'Catalog views inaccuracies in DB. Run DBCC UPDATEUSAGE'
				WHEN logmsg LIKE 'Error: 2511%' THEN 'Index Keys errors'
				WHEN logmsg LIKE 'Error: 3271%' THEN 'IO nonrecoverable error'
				WHEN logmsg LIKE 'Error: 5228%' OR logmsg LIKE 'Error: 5229%' THEN 'Online Index operation errors'
				WHEN logmsg LIKE 'Error: 5242%' THEN 'Page structural inconsistency'
				WHEN logmsg LIKE 'Error: 5243%' THEN 'In-memory structural inconsistency'
				WHEN logmsg LIKE 'Error: 5250%' THEN 'Corrupt page. Error cannot be fixed'
				WHEN logmsg LIKE 'Error: 5901%' THEN 'Chkpoint failed. Possible corruption'
				WHEN logmsg LIKE 'Error: 17130%' THEN 'No lock memory'
				WHEN logmsg LIKE 'Error: 17300%' THEN 'Unable to run new system task'
				WHEN logmsg LIKE 'Error: 802%' THEN 'No BP memory'
				WHEN logmsg LIKE 'Error: 845%' OR logmsg LIKE 'Error: 1105%' OR logmsg LIKE 'Error: 1121%' THEN 'No disk space available'
				WHEN logmsg LIKE 'Error: 1214%' THEN 'Internal parallelism error'
				WHEN logmsg LIKE 'Error: 823%' OR logmsg LIKE 'Error: 824%' THEN 'IO failure. Possible corruption'
				WHEN logmsg LIKE 'Error: 832%' THEN 'Page checksum error. Possible corruption'
				WHEN logmsg LIKE 'Error: 3624%' OR logmsg LIKE 'Error: 17065%' OR logmsg LIKE 'Error: 17066%' OR logmsg LIKE 'Error: 17067%' THEN 'System assertion check failed. Possible corruption'
				WHEN logmsg LIKE 'Error: 5572%' THEN 'Possible FILESTREAM corruption'
				WHEN logmsg LIKE 'Error: 9100%' THEN 'Possible index corruption'
				-- How To Diagnose and Correct Errors 17883, 17884, 17887, and 17888 (http://technet.microsoft.com/en-us/library/cc917684.aspx)
				WHEN logmsg LIKE 'Error: 17883%' THEN 'Non-yielding scheduler: http://technet.microsoft.com/en-us/library/cc917684.aspx'
				WHEN logmsg LIKE 'Error: 17884%' OR logmsg LIKE 'Error: 17888%' THEN 'Deadlocked scheduler: http://technet.microsoft.com/en-us/library/cc917684.aspx'
				WHEN logmsg LIKE 'Error: 17887%' THEN 'IO completion error: http://technet.microsoft.com/en-us/library/cc917684.aspx'
				WHEN logmsg LIKE 'Error: 1205%' THEN 'Deadlocked transaction'
				WHEN logmsg LIKE 'Error: 610%' THEN 'Page header invalid. Possible corruption'
				WHEN logmsg LIKE 'Error: 8621%' THEN 'QP stack overflow during optimization. Please simplify the query'
				WHEN logmsg LIKE 'Error: 8642%' THEN 'QP insufficient threads for parallelism'
				WHEN logmsg LIKE 'Error: 701%' THEN 'Insufficient memory'
				WHEN logmsg LIKE 'Error: 605%' THEN 'Page retrieval failed. Possible corruption'
				-- How to troubleshoot Msg 5180 (http://support.microsoft.com/kb/2015747)
				WHEN logmsg LIKE 'Error: 5180%' THEN 'Invalid file ID. Possible corruption: http://support.microsoft.com/kb/2015747'
				WHEN logmsg LIKE 'Error: 8966%' THEN 'Unable to read and latch on a PFS or GAM page'
				WHEN logmsg LIKE 'Error: 9001%' OR logmsg LIKE 'Error: 9002%' THEN 'Transaction log errors.'
				WHEN logmsg LIKE 'Error: 9003%' OR logmsg LIKE 'Error: 9004%' OR logmsg LIKE 'Error: 9015%' THEN 'Transaction log errors. Possible corruption'
				-- How to reduce paging of buffer pool memory in the 64-bit version of SQL Server (http://support.microsoft.com/kb/918483)
				WHEN logmsg LIKE 'A significant part of sql server process memory has been paged out%' THEN 'SQL Server process was trimmed by the OS. Preventable if LPIM is granted'
				WHEN logmsg LIKE '%cachestore flush%' THEN 'CacheStore flush'
			ELSE '' END AS [Comment],
			CASE WHEN logmsg LIKE 'Error: %' THEN (SELECT REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(text,'%.*ls','%'),'%d','%'),'%ls','%'),'%S_MSG','%'),'%S_PGID','%'),'%#016I64x','%'),'%p','%'),'%08x','%'),'%u','%'),'%I64d','%'),'%s','%'),'%ld','%'),'%lx','%'), '%%%', '%') 
					FROM sys.messages WHERE message_id = (CONVERT(int, RIGHT(LEFT(cte_dbcc.logmsg, CHARINDEX(',', cte_dbcc.logmsg)-1), CHARINDEX(',', cte_dbcc.logmsg)-8))) AND language_id = @langid) 
				ELSE '' END AS [Look_for_Message_example]
		FROM cte_dbcc
		GROUP BY err, logmsg
		ORDER BY SUM(errcnt) DESC;
		
		SELECT 'Errorlog_Detail' AS [Information], logid AS [Errorlog_Id], logdate AS [Logged_Date], spid AS [Process], logmsg AS [Logged_Message], 
			CASE WHEN logmsg LIKE 'Error: 825%' THEN 'IO transient failure. Possible corruption'
				WHEN logmsg LIKE 'Error: 833%' OR logmsg LIKE 'SQL Server has encountered % longer than 15 seconds %' THEN 'Long IO detected'
				WHEN logmsg LIKE 'Error: 855%' OR logmsg LIKE 'Error: 856%' THEN 'Hardware memory corruption'
				WHEN logmsg LIKE 'Error: 3452%' THEN 'Metadata inconsistency in DB. Run DBCC CHECKIDENT'
				WHEN logmsg LIKE 'Error: 3619%' THEN 'Chkpoint failed. No Log space available'
				WHEN logmsg LIKE 'Error: 9002%' THEN 'No Log space available'
				WHEN logmsg LIKE 'Error: 17179%' THEN 'No AWE - LPIM related'
				WHEN logmsg LIKE 'Error: 17890%' THEN 'sqlservr process paged out'
				WHEN logmsg LIKE 'Error: 17204%' OR logmsg LIKE 'Error: 17207%' THEN 'Error opening file during startup process'
				WHEN logmsg LIKE 'Error: 2508%' THEN 'Catalog views inaccuracies in DB. Run DBCC UPDATEUSAGE'
				WHEN logmsg LIKE 'Error: 2511%' THEN 'Index Keys errors'
				WHEN logmsg LIKE 'Error: 3271%' THEN 'IO nonrecoverable error'
				WHEN logmsg LIKE 'Error: 5228%' OR logmsg LIKE 'Error: 5229%' THEN 'Online Index operation errors'
				WHEN logmsg LIKE 'Error: 5242%' THEN 'Page structural inconsistency'
				WHEN logmsg LIKE 'Error: 5243%' THEN 'In-memory structural inconsistency'
				WHEN logmsg LIKE 'Error: 5250%' THEN 'Corrupt page. Error cannot be fixed'
				WHEN logmsg LIKE 'Error: 5901%' THEN 'Chkpoint failed. Possible corruption'
				WHEN logmsg LIKE 'Error: 17130%' THEN 'No lock memory'
				WHEN logmsg LIKE 'Error: 17300%' THEN 'Unable to run new system task'
				WHEN logmsg LIKE 'Error: 802%' THEN 'No BP memory'
				WHEN logmsg LIKE 'Error: 845%' OR logmsg LIKE 'Error: 1105%' OR logmsg LIKE 'Error: 1121%' THEN 'No disk space available'
				WHEN logmsg LIKE 'Error: 1214%' THEN 'Internal parallelism error'
				WHEN logmsg LIKE 'Error: 823%' OR logmsg LIKE 'Error: 824%' THEN 'IO failure. Possible corruption'
				WHEN logmsg LIKE 'Error: 832%' THEN 'Page checksum error. Possible corruption'
				WHEN logmsg LIKE 'Error: 3624%' OR logmsg LIKE 'Error: 17065%' OR logmsg LIKE 'Error: 17066%' OR logmsg LIKE 'Error: 17067%' THEN 'System assertion check failed. Possible corruption'
				WHEN logmsg LIKE 'Error: 5572%' THEN 'Possible FILESTREAM corruption'
				WHEN logmsg LIKE 'Error: 9100%' THEN 'Possible index corruption'
				-- How To Diagnose and Correct Errors 17883, 17884, 17887, and 17888 (http://technet.microsoft.com/en-us/library/cc917684.aspx)
				WHEN logmsg LIKE 'Error: 17883%' THEN 'Non-yielding scheduler'
				WHEN logmsg LIKE 'Error: 17884%' OR logmsg LIKE 'Error: 17888%' THEN 'Deadlocked scheduler'
				WHEN logmsg LIKE 'Error: 17887%' THEN 'IO completion error'
				WHEN logmsg LIKE 'Error: 1205%' THEN 'Deadlocked transaction'
				WHEN logmsg LIKE 'Error: 610%' THEN 'Page header invalid. Possible corruption'
				WHEN logmsg LIKE 'Error: 8621%' THEN 'QP stack overflow during optimization. Please simplify the query'
				WHEN logmsg LIKE 'Error: 8642%' THEN 'QP insufficient threads for parallelism'
				WHEN logmsg LIKE 'Error: 701%' THEN 'Insufficient memory'
				WHEN logmsg LIKE 'Error: 605%' THEN 'Page retrieval failed. Possible corruption'
				-- How to troubleshoot Msg 5180 (http://support.microsoft.com/kb/2015747)
				WHEN logmsg LIKE 'Error: 5180%' THEN 'Invalid file ID. Possible corruption'
				WHEN logmsg LIKE 'Error: 8966%' THEN 'Unable to read and latch on a PFS or GAM page'
				WHEN logmsg LIKE 'Error: 9001%' OR logmsg LIKE 'Error: 9002%' THEN 'Transaction log errors.'
				WHEN logmsg LIKE 'Error: 9003%' OR logmsg LIKE 'Error: 9004%' OR logmsg LIKE 'Error: 9015%' THEN 'Transaction log errors. Possible corruption'
				-- How to reduce paging of buffer pool memory in the 64-bit version of SQL Server (http://support.microsoft.com/kb/918483)
				WHEN logmsg LIKE 'A significant part of sql server process memory has been paged out%' THEN 'SQL Server process was trimmed by the OS. Preventable if LPIM is granted'
				WHEN logmsg LIKE '%cachestore flush%' THEN 'CacheStore flush'
			ELSE '' END AS [Comment]
		FROM #dbcc
		ORDER BY logdate DESC
	END
	ELSE
	BEGIN
		SELECT 'Errorlog' AS [Check], '[OK]' AS [Deviation]
	END;
END
ELSE
BEGIN
	RAISERROR('[WARNING: Only a sysadmin or securityadmin can run the "Errorlog" check. Bypassing check]', 16, 1, N'permissions')
	RAISERROR('[WARNING: If not sysadmin or securityadmin, then user must be a granted EXECUTE permissions on the following sprocs to run checks: xp_enumerrorlogs and sp_readerrorlog. Bypassing check]', 16, 1, N'extended_sprocs')
	--RETURN
END;

--------------------------------------------------------------------------------------------------------------------------------
-- Clean up temp objects 
--------------------------------------------------------------------------------------------------------------------------------
RAISERROR (N'Clearing up temporary objects', 10, 1) WITH NOWAIT

IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbinfo%') 
DROP TABLE #dbinfo;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#output_dbinfo%') 
DROP TABLE #output_dbinfo;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIOStall%') 
DROP TABLE #tblIOStall;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs1%') 
DROP TABLE #tmpdbs1;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tmpdbs2%') 
DROP TABLE #tmpdbs2;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblPerfCount%') 
DROP TABLE #tblPerfCount;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblHypObj%') 
DROP TABLE #tblHypObj;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs1%') 
DROP TABLE #tblIxs1;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs2%') 
DROP TABLE #tblIxs2;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs3%') 
DROP TABLE #tblIxs3;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs4%') 
DROP TABLE #tblIxs4;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblIxs5%') 
DROP TABLE #tblIxs5;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFK%') 
DROP TABLE #tblFK;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#dbcc%') 
DROP TABLE #dbcc;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#avail_logs%') 
DROP TABLE #avail_logs;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info1%') 
DROP TABLE #log_info1;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#log_info2%') 
DROP TABLE #log_info2;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblWaits%')
DROP TABLE #tblWaits;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFinalWaits%')
DROP TABLE #tblFinalWaits;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblLatches%')
DROP TABLE #tblLatches;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#tblFinalLatches%')
DROP TABLE #tblFinalLatches;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#IndexCreation%')
DROP TABLE #IndexCreation;
IF EXISTS (SELECT [object_id] FROM tempdb.sys.objects (NOLOCK) WHERE [name] LIKE '#IndexRedundant%')
DROP TABLE #IndexRedundant;
EXEC ('USE tempdb; IF EXISTS (SELECT 1 FROM tempdb.sys.objects WHERE name = N''fn_createindex_keycols'') DROP FUNCTION dbo.fn_createindex_keycols')
EXEC ('USE tempdb; IF EXISTS (SELECT 1 FROM tempdb.sys.objects WHERE name = N''fn_createindex_allcols'') DROP FUNCTION dbo.fn_createindex_allcols')
EXEC ('USE tempdb; IF EXISTS (SELECT 1 FROM tempdb.sys.objects WHERE name = N''fn_createindex_includecols'') DROP FUNCTION dbo.fn_createindex_includecols')
RAISERROR (N'All done!', 10, 1) WITH NOWAIT
GO