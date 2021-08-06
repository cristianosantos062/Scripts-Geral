declare @banco sysname = 'GI_GestaoIntegrada_SOMPO'

--> Declaracao das Variaveis
	declare @str 		varchar(800)
	declare @cont 		int
	declare @SQLString 	nvarchar(1000)
	declare @tamanholog	dec(17,2)


set @banco = upper(@banco)

--> Cria tabela temporaria
CREATE TABLE #tbEspacoBanco (
	[Banco] [varchar] (70) COLLATE SQL_Latin1_General_CP1_CI_AI NULL ,
	[FileGroup] sysname NULL,
	[TamanhoBanco]	[decimal](17, 2) NULL ,
	[TamanhoLog]	[decimal](17, 2) NULL ,
	[EspacoUsado]	[decimal](17, 2) NULL ,
	[EspacoLivre]	[decimal](17, 2) NULL ) 

--> Cria Tabela Temporaria
create table #tbFile ( fileid smallint, groupid smallint, filename varchar(256)) 

if @banco is not null
begin

	--> Verifica se o banco existe
	if not exists (select 1 from master..sysdatabases where name = @banco )
	begin
		select 'Banco de Dados nao EXISTE' as Banco
		drop table #tbFile
		return
	end
	
	if DATABASEPROPERTY(@banco, 'IsInLoad')  = 1
	begin
		select 'Banco em load' as Banco
		drop table #tbFile
		return
	end

	--> Tamanho do Log
	set @SQLString = N'select @tamanholog =  CAST( ( sum(f.size) * 8 ) / 1024. AS numeric( 17, 2 ) ) FROM '+@banco+'.dbo.sysfiles AS f where (f.status & 64 <> 0)'
	EXECUTE sp_executesql @SQLString, N'@tamanholog int OUTPUT',@tamanholog OUTPUT
	
	--> 	

	set @SQLString = N'use '+@banco+char(13)+'select '''+@banco+' - ''+ substring(f.name,1,30) as Banco, g.groupname as [FileGroup],
	  CAST( ( f.size * 8 ) / 1024. AS numeric( 17, 2 ) ) as [Tamanho Banco (MB)],'+cast(@tamanholog as nvarchar(20))+' as [Tamanho Log (MB)],
          CAST( ( FILEPROPERTY( f.name, ''SpaceUsed'' ) * 8 ) / 1024.  AS numeric( 17, 2 ) ) as [Espaco Usado (MB)],
	  CAST( ( ( f.size - FILEPROPERTY( f.name, ''SpaceUsed'' )) * 8 )
			   / 1024.  AS numeric( 17, 2 ) ) as [Espaco Livre (MB)]
	  FROM '+@banco+'.dbo.sysfiles AS f join ' + @banco+'.dbo.sysfilegroups g on f.groupid = g.groupid where (f.status & 64 = 0)'
  
	insert into #tbEspacoBanco EXECUTE sp_executesql @SQLString, N'@tamanholog int',@tamanholog
	select Banco, FileGroup, 
	Cast(Replace(TamanhoBanco,'.',',') as Varchar (17)) as [TamanhoBanco (MB)],
	Cast(Replace(TamanhoLog,'.',',') as Varchar (17)) as [TamanhoLog (MB)], 
	Cast(Replace(EspacoUsado,'.',',')as Varchar (17)) as [EspacoUsado (MB)], 
	Cast(Replace(EspacoLivre,'.',',') as Varchar (17)) as [EspacoLivre (MB] 
	from #tbEspacoBanco
	
	select FileGroup, 
	Cast(replace(sum (isnull(TamanhoBanco,0)),'.',',') as Varchar (17)) as [TamanhoFileGroup (MB)],
	Cast(replace(sum(isnull(EspacoUsado,0)),'.',',') as Varchar(17)) as [EspacoUsado (MB)], 
	Cast(replace(sum(isnull (EspacoLivre,0)),'.',',') as Varchar (17)) as [EspacoLivre (MB)],
	--CAST((sum(isnull (EspacoLivre,0))*100)/sum (isnull(TamanhoBanco,0)) AS numeric(10,2)) as [Percent Livre] 
	Cast(replace(Cast((sum(isnull(EspacoLivre,0))*100)/sum (isnull(TamanhoBanco,0)) AS numeric(17,2)),'.',',') as Varchar(17)) as [Percent Livre] 
	from #tbEspacoBanco
	group by filegroup
	order by filegroup
end
drop table #tbEspacoBanco
drop table #tbFile