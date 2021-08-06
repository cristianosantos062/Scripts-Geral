use mn_gestaointegrada
go

/*****************************************************************************************************************************
	Data de criação :31/03/2017
	Autor Criação  : Cristiano Santos da Silva
	Objetivo da criação: Executar Update statistics 
	Sistemas que utilizam : Gestao Integrada
	Exemplos de execução:
		exec p_DBReindex gestao_integrada, 'F' (Update statisitcs Full Scan do banco gestao_integrada)
		exec p_DBReindex gestao_integrada, 'F' (Update statisitcs Sampled do banco gestao_integrada)

	Histórico:  

******************************************************************************************************************************/

alter PROCEDURE p_DBUpdStat ( @DBName sysname,  -- Nome do Banco de dados
							  @Modo varchar(10) -- 'F' para atualizacao com Full Scan e 'S' para atualização Sampled
							 )

as

Declare @tabela varchar (255),
		@indice varchar (255),
		@linhasestatistica int,
		@porcetagemmodificacao int,
		@t_sql varchar (max),
		@DBID int = db_id(@DBName)


-----------------------------------------------------------------------------------------------
-- Tabelas de controle de quais tableas terão atualização de Estatísticas					 --
-----------------------------------------------------------------------------------------------

IF  OBJECT_ID('tempdb..#sysname') > 0
	DROP TABLE tempdb..#sysname

IF  OBJECT_ID('tempdb..#sysname01') > 0
	DROP TABLE tempdb..#sysname01

create table #sysname (Banco varchar(255), name varchar(255), id int, indid int, rowcnt int, rowmodctr int)
	insert #sysname exec sp_msforeachdb 'use [?]; select ''?'', name, id, indid, rowcnt, rowmodctr from sys.sysindexes'

	select * into #sysname01 from #sysname WHERE BANCO = @DBName

		IF  OBJECT_ID('tempdb..#t_atualiza_estatistica') > 0
			DROP TABLE tempdb..#t_atualiza_estatistica


create table #t_atualiza_estatistica (	banco varchar (255),
										tabela varchar (255), 
										indice varchar (255), 
										linhasestatistica decimal(20,2), 
										linhasmodificadas decimal(20,2), 
										porcetagemmodificacao decimal(20,2)
									  )

-----------------------------------------------------------------------------------------------
-- Carrega tabela apenas com todos os índices												 --
-----------------------------------------------------------------------------------------------
	insert #t_atualiza_estatistica
				select distinct
				db_name(database_id) Banco,
				object_name (ius.object_id, database_id) Tabela,
				s.name Indice,
				s.rowcnt,
				s.rowmodctr,
				cast (100*(cast (s.rowmodctr as decimal (20,2))/cast (s.rowcnt as decimal (20,2))) as decimal (10,2)) as mod_in_percent
			from #sysname01 s
			join sys.dm_db_index_usage_stats ius
				on s.id = ius.object_id and s.indid = ius.index_id  
			where ius.database_id = @DBID
				--and ius.index_id > 0
				and rowcnt > 0
				and s.rowmodctr > 0
			
	
-----------------------------------------------------------------------------------------------
-- Quantidade de índices e tablelas encontradas												 --
-----------------------------------------------------------------------------------------------
	select cast (count(*) as varchar) + ' índices encontrados' from #t_atualiza_estatistica


--------------------------------------------------------------------------------------------------
-- Atualização de estatisticas para opção Sampled para todos os índices ou tabelas que tiveram  -- 
-- mais que 1% de linhas modificadas															--
--------------------------------------------------------------------------------------------------
if @Modo =  'S'
begin
	DECLARE AtualizaEstat CURSOR  
		FOR  SELECT distinct banco, tabela, indice FROM #t_atualiza_estatistica where porcetagemmodificacao > 1 -- (>1%)
	OPEN AtualizaEstat
	FETCH AtualizaEstat into @DBName, @tabela, @indice
			WHILE @@FETCH_STATUS = 0 
			BEGIN  
			 if @indice is not null
			 begin
				select @t_sql = 'update statistics [' + @DBName + '].[dbo].[' + tabela + '] [' + indice + ']' from #t_atualiza_estatistica 
						where indice = @indice and tabela = @tabela 
				print cast (getdate() as varchar) + ' - ' + @DBName + ' - ' + @t_sql
				exec (@t_sql)
			 end
			 if @indice is null
			 begin
				select @t_sql = 'update statistics [' + @DBName + '].[dbo].[' + tabela + ']' from #t_atualiza_estatistica 
						where indice = @indice and tabela = @tabela 
				print cast (getdate() as varchar) + ' - ' + @DBName + ' - ' + @t_sql
				exec (@t_sql)
			 end
				Fetch AtualizaEstat Into @DBName, @tabela, @indice
			END
		CLOSE AtualizaEstat
		DEALLOCATE AtualizaEstat
end

-----------------------------------------------------------------------------------------------
-- Atualização de estatisticas para opção Full Scan para todas as tabelas					 --
-----------------------------------------------------------------------------------------------
if @Modo =  'F'
begin
	DECLARE AtualizaEstat CURSOR  
		FOR  SELECT distinct banco, tabela, indice FROM #t_atualiza_estatistica
	OPEN AtualizaEstat
	FETCH AtualizaEstat into @DBName, @tabela, @indice
			WHILE @@FETCH_STATUS = 0 
			BEGIN  
			 if @indice is not null
			 begin
				select @t_sql = 'update statistics [' + @DBName + '].[dbo].[' + tabela + '] [' + indice + '] with fullscan' from #t_atualiza_estatistica 
						where indice = @indice and tabela = @tabela 
				print cast (getdate() as varchar) + ' - ' + @DBName + ' - ' + @t_sql
				exec (@t_sql)
			 end
			 if @indice is null
			 begin
				select @t_sql = 'update statistics [' + @DBName + '].[dbo].[' + tabela + '] with fullscan' from #t_atualiza_estatistica 
						where indice = @indice and tabela = @tabela 
				print cast (getdate() as varchar) + ' - ' + @DBName + ' - ' + @t_sql
				exec (@t_sql)
			 end
				Fetch AtualizaEstat Into @DBName, @tabela, @indice
			END
		CLOSE AtualizaEstat
		DEALLOCATE AtualizaEstat
end