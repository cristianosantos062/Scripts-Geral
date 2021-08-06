use gestao_integrada
SELECT distinct
	--'drop index ' + b.name + ' on ' +  object_name(a.object_id),
	--a.index_id,
	db_name(a.database_id) banco,
	object_name(a.object_id) tabela,
	b.name indice, 
	a.user_seeks, 
	a.user_scans, 
	a.user_lookups,
	--a.user_updates,
	b.dpages*8/1024 tamanho_MB
	--a.last_system_update,
	--a.last_user_update

FROM monitorsql..t_dm_db_index_usage_stats_hist a 
inner join sysindexes b 
	on a.object_id = b.id and a.index_id = b.indid

WHERE	-- object_name(a.object_id) = 'tbpbm_vendas_arquivo' and 
		 a.user_seeks = 0 
		and a.user_lookups = 0 
		and a.user_scans = 0
		and a.index_id > 1
		order by 6 desc