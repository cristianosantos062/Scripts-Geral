use data_source
go
declare @tsql varchar(255),
		@idtabela int,
		@nometabela varchar(255)
declare @dbID int = db_id()

--> tabela de controle de quais indices serão atualizados

IF  OBJECT_ID('tempdb..#tab_reindex') > 0
			DROP TABLE tempdb..#tab_reindex

create table #tab_reindex
		(idtabela int, nometabela varchar(100), tipoindex varchar(50), numeropagina int)
	
	-- Insere os índices selecionados para executar o rebuild
	insert #tab_reindex
			select object_id,
				   OBJECT_NAME(object_id), 
				   index_type_desc, 
				   page_count
			from master.sys.dm_db_index_physical_stats(@dbID, null, NULL, NULL, NULL)
				  where avg_fragmentation_in_percent> 10


--> Cursor para executar o comando de rebuild da menor para a maior tabela

	DECLARE RebuildIndice CURSOR  
		FOR   SELECT idtabela FROM #tab_reindex order by numeropagina asc

	OPEN RebuildIndice
	FETCH RebuildIndice into @idtabela 
		WHILE @@FETCH_STATUS = 0 
		BEGIN  
			--checkpoint
			select @nometabela = nometabela from #tab_reindex where idtabela = @idtabela  
			print ' Executando rebuild da tabela ' + @nometabela + ' ...'
			if 'HEAP' IN (select tipoindex from #tab_reindex where idtabela = @idtabela)
			  begin

			    select @tsql =  'alter table ' + nometabela + ' rebuild'	from #tab_reindex where idtabela = @idtabela
			  end
			else 
			  begin
				select @tsql =  'alter index all on ' + nometabela + ' rebuild' from #tab_reindex where idtabela = @idtabela
			  end
			exec (@tsql)
			Fetch RebuildIndice Into @idtabela
		END
	CLOSE RebuildIndice  
	DEALLOCATE RebuildIndice

		drop table #tab_reindex