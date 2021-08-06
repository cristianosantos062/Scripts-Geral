/***Campos em um indice ****/

SELECT Object_name(I.object_id) as NomeTabela, I.type_desc,Cl.name NomeColuna ,C.is_included_column
FROM       SYS.INDEXES       as I
inner join sys.index_columns as C on I.Object_id=C.Object_id and I.index_id=C.index_id
inner join sys.columns       as CL on C.column_id=CL.column_id and Cl.object_id=C.object_id
--WHERE I.NAME LIKE 'IdxNPatData'



/***Indices usados para resolver Queries " Executar por banco de dados" ***/

SELECT Db_name(ddius.Database_id),OBJECT_NAME(ddius.[object_id], ddius.database_id) AS [object_name] ,
ddius.index_id ,
ddius.user_seeks ,
ddius.user_scans ,
ddius.user_lookups ,
ddius.user_seeks + ddius.user_scans + ddius.user_lookups
AS user_reads ,
ddius.user_updates AS user_writes ,
ddius.last_user_scan ,
ddius.last_user_update
FROM sys.dm_db_index_usage_stats ddius
WHERE ddius.database_id > 4 -- filter out system tables
AND OBJECTPROPERTY(ddius.object_id, 'IsUserTable') = 1
AND ddius.index_id > 0 -- filter out heaps
and Last_user_update is not null
ORDER BY user_reads DESC


/***indices nunca usados ***/


SELECT Db_name(DB_ID())DatabaseName,OBJECT_NAME(i.[object_id]) AS [Table Name] ,
i.name
FROM sys.indexes AS i
INNER JOIN sys.objects AS o ON i.[object_id] = o.[object_id]
WHERE i.index_id NOT IN ( SELECT ddius.index_id
FROM sys.dm_db_index_usage_stats AS ddius
WHERE ddius.[object_id] = i.[object_id]
AND i.index_id = ddius.index_id
AND database_id = DB_ID() )
AND o.[type] = 'U'
ORDER BY OBJECT_NAME(i.[object_id]) ASC ;

/***Indices mantidos , mas não são usados "Executar por banco" ***/


SELECT '[' + DB_NAME() + '].[' + su.[name] + '].[' + o.[name] + ']'
AS [statement] ,
i.[name] AS [index_name] ,
ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups]
AS [user_reads] ,
ddius.[user_updates] AS [user_writes] ,
SUM(SP.rows) AS [total_rows]
,SUM(s.[used_page_count]) * 8/1024 AS IndexSizekB
FROM sys.dm_db_index_usage_stats ddius
INNER JOIN sys.indexes i ON ddius.[object_id] = i.[object_id]
AND i.[index_id] = ddius.[index_id]
INNER JOIN sys.partitions SP ON ddius.[object_id] = SP.[object_id]
AND SP.[index_id] = ddius.[index_id]
INNER JOIN sys.objects o ON ddius.[object_id] = o.[object_id]
INNER JOIN sys.sysusers su ON o.[schema_id] = su.[UID]
LEFT JOIN sys.dm_db_partition_stats AS s ON s.[object_id] = i.[object_id]
WHERE ddius.[database_id] = DB_ID() -- current database only
AND OBJECTPROPERTY(ddius.[object_id], 'IsUserTable') = 1
AND ddius.[index_id] > 1
GROUP BY su.[name] ,
o.[name] ,
i.[name] ,
ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups] ,
ddius.[user_updates]
HAVING ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups] = 0
ORDER BY ddius.[user_updates] DESC ,
su.[name] ,
o.[name] ,
i.[name ]


/* Para gerar o script que irá excluir os indices que são mantidos mas não são usados */

SELECT 'DROP INDEX [' + i.[name] + '] ON [' + su.[name] + '].[' + o.[name]
+ '] WITH ( ONLINE = OFF )' AS [drop_command]

FROM sys.dm_db_index_usage_stats ddius
INNER JOIN sys.indexes i ON ddius.[object_id] = i.[object_id]
AND i.[index_id] = ddius.[index_id]
INNER JOIN sys.partitions SP ON ddius.[object_id] = SP.[object_id]
AND SP.[index_id] = ddius.[index_id]
INNER JOIN sys.objects o ON ddius.[object_id] = o.[object_id]
INNER JOIN sys.sysusers su ON o.[schema_id] = su.[UID]
WHERE ddius.[database_id] = DB_ID() -- current database only
AND OBJECTPROPERTY(ddius.[object_id], 'IsUserTable') = 1
AND ddius.[index_id] > 0
GROUP BY su.[name] ,
o.[name] ,
i.[name] ,
ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups] ,
ddius.[user_updates]
HAVING ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups] = 0
ORDER BY ddius.[user_updates] DESC ,
su.[name] ,
o.[name] ,
i.[name ]








/*Indices potencialmente ineficientes "NONCLUSTERED"  Escritas > leituras*/




SELECT OBJECT_NAME(ddius.[object_id]) AS [Table Name] ,
i.name AS [Index Name] ,
i.index_id ,
user_updates AS [Total Writes] ,
user_seeks + user_scans + user_lookups AS [Total Reads] ,
user_updates - ( user_seeks + user_scans + user_lookups )
AS [Difference]
FROM sys.dm_db_index_usage_stats AS ddius WITH ( NOLOCK )
INNER JOIN sys.indexes AS i WITH ( NOLOCK )
ON ddius.[object_id] = i.[object_id]
AND i.index_id = ddius.index_id
WHERE OBJECTPROPERTY(ddius.[object_id], 'IsUserTable') = 1
AND ddius.database_id = DB_ID()
AND user_updates > ( user_seeks + user_scans + user_lookups )
AND i.index_id > 1
ORDER BY [Difference] DESC ,
[Total Writes] DESC ,
[Total Reads] ASC ;




/***Indices não usados para leitura de usuários *****/




SELECT '[' + DB_NAME() + '].[' + su.[name] + '].[' + o.[name] + ']'
AS [statement] ,
i.[name] AS [index_name] ,
ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups]
AS [user_reads] ,
ddius.[user_updates] AS [user_writes] ,
ddios.[leaf_insert_count] ,
ddios.[leaf_delete_count] ,
ddios.[leaf_update_count] ,
ddios.[nonleaf_insert_count] ,
ddios.[nonleaf_delete_count] ,
ddios.[nonleaf_update_count]
FROM sys.dm_db_index_usage_stats ddius
INNER JOIN sys.indexes i ON ddius.[object_id] = i.[object_id]
AND i.[index_id] = ddius.[index_id]
INNER JOIN sys.partitions SP ON ddius.[object_id] = SP.[object_id]
AND SP.[index_id] = ddius.[index_id]
INNER JOIN sys.objects o ON ddius.[object_id] = o.[object_id]
INNER JOIN sys.sysusers su ON o.[schema_id] = su.[UID]
INNER JOIN sys.[dm_db_index_operational_stats](DB_ID(), NULL, NULL,
NULL)
AS ddios
ON ddius.[index_id] = ddios.[index_id]
AND ddius.[object_id] = ddios.[object_id]
AND SP.[partition_number] = ddios.[partition_number]
AND ddius.[database_id] = ddios.[database_id]
WHERE OBJECTPROPERTY(ddius.[object_id], 'IsUserTable') = 1
AND ddius.[index_id] > 0
AND ddius.[user_seeks] + ddius.[user_scans] + ddius.[user_lookups] = 0
ORDER BY ddius.[user_updates] DESC ,
su.[name] ,
o.[name] ,
i.[name ]



-- DETECTANDO FRAGMENTAÇÃO DE INDICES

SELECT '[' + DB_NAME() + '].[' + OBJECT_SCHEMA_NAME(ddips.[object_id],
 DB_ID()) + '].['
 + OBJECT_NAME(ddips.[object_id], DB_ID()) + ']' AS [statement] ,
 i.[name] AS [index_name] ,
 ddips.[index_type_desc] ,
 ddips.[partition_number] ,
 ddips.[alloc_unit_type_desc] ,
 ddips.[index_depth] ,
 ddips.[index_level] ,
 CAST(ddips.[avg_fragmentation_in_percent] AS SMALLINT)
 AS [avg_frag_%] ,
 CAST(ddips.[avg_fragment_size_in_pages] AS SMALLINT)
 AS [avg_frag_size_in_pages] ,
 ddips.[fragment_count] ,
 ddips.[page_count]
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL,
 NULL, NULL, NULL) ddips
 INNER JOIN sys.[indexes] i ON ddips.[object_id] = i.[object_id]
 AND ddips.[index_id] = i.[index_id]
WHERE ddips.[avg_fragmentation_in_percent] > 15
 AND ddips.[page_count] > 500



-- Base com maior uso de memória

	  SELECT DB_NAME(DATABASE_ID) DatabaseName,(COUNT(*)*8)/1024 Memory_Used_MB FROM sys.dm_os_buffer_descriptors 
	  GROUP BY DB_NAME(DATABASE_ID)	  
	  ORDER BY 2 DESC
	  --COMPUTE SUM((COUNT(*)*8)/1024)





-- Relação de Estatísticas Desatualizadas 

SELECT name AS Estatística, STATS_DATE(object_id, stats_id) AS 'Data',Object_name(object_id) ObjectName,Name

FROM sys.stats

Where STATS_DATE(object_id, stats_id) <= Dateadd(D,-2, GetDate()) AND Object_name(object_id) NOT LIKE 'SYS%'

Order by Data Desc


/*** Gera script para atualizar estatistica ***/

SELECT 'update statistics ['+ cast(schema_name(T2.Schema_Id)as nvarchar(200)) +'].['+ cast(Object_name(T0.object_id) as nvarchar(200))+'] '+ T0.Name
FROM sys.stats T0 inner join sys.indexes T1 on T0.Object_id=T1.object_id and T0.name=T1.name
inner join sys.objects as t2 on T1.Object_id=T2.Object_id
Where STATS_DATE(T1.object_id, stats_id) <= Dateadd(D,-2, GetDate()) 
and  Object_name(T1.object_id) not like 'sys%' 
and  Object_name(T1.object_id) not like '%old%'
and  Object_name(T1.object_id) not like 'Ms%'
and  Object_name(T1.object_id) not like 'TMP%'
and  Object_name(T1.object_id) not like '%BKP%'
and  Object_name(T1.object_id) not like '%STG%'


select top 10 object_name(object_id),* from sys.indexes

select * from sys.objects 
select top 10 * from sys.schemas    

/***Após SQL Server 2008 R2 mas ainda pode usar o sys.stats ***/
select * from sys.dm_db_stats_properties (object_id, stats_id)




