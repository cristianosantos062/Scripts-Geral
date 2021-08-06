CREATE TABLE #CapacityBancos (
	--[NoCluster] sysname null,
	[database_id] int,
	[Banco] nvarchar(255) null,
	--[Sigla] varchar (15) null,
	[CaminhhoArquivo] nvarchar (2000) NULL,
	[TamanhoArquivo_MB] decimal(17, 2) NULL ,
	[EspacoUsado_MB] decimal(17, 2) NULL )
	--[EspacoLivre_MB] decimal(17, 2) NULL ) 
	
 
 insert into #CapacityBancos exec sp_msforeachdb 'use [?]; 
 						select 
							f.database_id,
							cast (DB_NAME(f.database_id) as nvarchar(255) ),
							cast (f.physical_name as nvarchar (2000)),
							CAST((f.size*8)/1024. AS numeric(17,2)),
							CAST(((f.size - FILEPROPERTY(f.name, ''SpaceUsed''))* 8)/1024.  AS numeric(17, 2))
														
						from sys.master_files f
						where f.database_id=DB_ID(DB_NAME()) and f.database_id>4 and f.file_id=1'

	
	
select 
	banco,
	EspacoUsado_MB,
	CAST ((TamanhoArquivo_MB - EspacoUsado_MB) as decimal(17,2)) as EspacoLivre_MB,
	CAST ((EspacoUsado_MB/TamanhoArquivo_MB)*100. as decimal(17,2)) as Percent_Livre,
	CAST((mf.size*8)/1024. AS numeric(17,2)) TamanhoLog_MB
from  #CapacityBancos cb
	join master.sys.master_files mf
on cb.database_id = mf.database_id
    where mf.file_id = 2
order by Banco asc


--drop table #CapacityBancos

select * from sys.master_files