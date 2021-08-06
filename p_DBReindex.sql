use MN_GestaoIntegrada
go
/*****************************************************************************************************************************
	Data de criação :31/03/2017
	Autor Criação  : Cristiano Santos da Silva
	Objetivo da criação: Executar rebild de índice e tabelas de bases de dados
	Sistemas que utilizam : Gestao Integrada
	Exemplos de execução:
		exec p_DBReindex gestao_integrada, 10 (rebuid das tabelas do banco gestao_integrada com fragmentação maior que 10%)
	Histórico:  

******************************************************************************************************************************/


ALTER procedure p_DBReindex (
				@DBName sysname, -- Nome do Banco de Dados 
				@frag int		 -- Limite de fragmentação em porcentagem considerada para realizar o rebuild de um índice ou tabela
			)

as

declare @tsql varchar(255),
		@idtabela int,
		@idindice int,
		@nometabela varchar(255),
		@nomeindice varchar (255)
declare @dbID int = db_id(@DBName)


------------------------------------------------------------------------------
-- Tabelas de controle de quais indices serão atualizados					--
------------------------------------------------------------------------------
IF  OBJECT_ID('tempdb..#sysname') > 0
		DROP TABLE tempdb..#sysname

IF  OBJECT_ID('tempdb..#sysname01') > 0
		DROP TABLE tempdb..#sysname01
			
IF  OBJECT_ID('tempdb..#tab_reindex') > 0
		DROP TABLE tempdb..#tab_reindex

create table #sysname (Banco varchar(255), Tabela varchar(255), id int, indid int, name varchar(255))
	insert #sysname exec sp_msforeachdb 'use [?]; select ''?'', object_name(id), id, indid, name from sysindexes'

	select * into #sysname01 from #sysname WHERE BANCO = @DBName

create table #tab_reindex
		(Banco varchar(255), idtabela int, nometabela varchar(255), idindice int, nomeindice varchar(255), tipoindex varchar(50), numeropagina int)


------------------------------------------------------------------------------
-- Insere os índices selecionados para executar o rebuild					--
------------------------------------------------------------------------------
print cast(getdate() as varchar ) + ' - Capturando tabelas para realizar o rebuild ' 
insert #tab_reindex
		select si.Banco,
			   si.id,
			   si.Tabela,
			   si.indid,
			   si.name,
			   index_type_desc,
			   page_count
		from master.sys.dm_db_index_physical_stats(@dbID, null, NULL, NULL, NULL) ips
		inner join #sysname01 si
			on ips.object_id = si.id and ips.index_id = si.indid
			  where avg_fragmentation_in_percent>= @frag
			

------------------------------------------------------------------------------
-- Cursor para executar o comando de rebuild da menor para a maior tabela   --
------------------------------------------------------------------------------

DECLARE RebuildIndice CURSOR  
	FOR   SELECT  banco, idtabela, idindice FROM #tab_reindex order by numeropagina asc

OPEN RebuildIndice
FETCH RebuildIndice into @DBName, @idtabela, @idindice 
	WHILE @@FETCH_STATUS = 0 
	BEGIN  
		checkpoint
		select @nometabela = nometabela from #tab_reindex where idtabela = @idtabela
		select @nomeindice = nomeindice from #tab_reindex where idtabela = @idtabela and idindice = @idindice
		if @idindice <> 0
		begin
			select @tsql =  'alter index [' + nomeindice + '] on [' + Banco + '].[dbo].[' + nometabela + '] rebuild' from #tab_reindex where idtabela = @idtabela
			print cast(getdate() as varchar ) + ' - ' + @DBName + ' - Executando rebuild do indice ' + @nomeindice + ' da tabela ' + @nometabela + ': ' + @tsql
			exec (@tsql)
		end
		if @idindice = 0
		  begin
			select @tsql =  'alter table [' + Banco + '].[dbo].[' + nometabela + '] rebuild' from #tab_reindex where idtabela = @idtabela
			print cast(getdate() as varchar )  + ' - ' + @DBName +  ' - Executando rebuild da tabela ' + @nometabela + ': ' + @tsql
			exec (@tsql)
		  end
		Fetch RebuildIndice Into @DbName, @idtabela, @idindice
	END
CLOSE RebuildIndice  
DEALLOCATE RebuildIndice

drop table #tab_reindex