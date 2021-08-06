declare @database varchar(100) = null

if exists (select * from tempdb..sysobjects where name like '%#T_log%' and xtype = 'U')
	drop table #T_log

create table #T_log (
			[DatabaseID] as db_id([DatabaseName]),
			[DatabaseName] varchar(100), 
			[TamanhoLogMB] decimal(10,2), 
			[PercentUsado] decimal(10,2), 
			[status] int, 
			[EspacoUsadoMB] as cast (PercentUsado*TamanhoLogMB/100 as decimal (10,2)),
			[DataColeta] datetime default getdate()
		)

declare @execDBCC nvarchar (25) =  'dbcc sqlperf(logspace)'

insert #T_log (	[DatabaseName], [TamanhoLogMB], [PercentUsado], [status] )
	EXECUTE sp_executesql @execDBCC

if @database is not null
	select * from #T_log where DatabaseName = @database
else 
	select * from #T_log order by TamanhoLogMB desc