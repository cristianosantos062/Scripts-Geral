use funcional_sgs
SELECT 
	object_name(a.object_id) tabela,
	a.index_id,
	b.name indice, 
	a.user_seeks, 
	a.user_scans, 
	a.user_lookups,
	a.user_updates,
	b.dpages*8/1024 tamanho_MB,
	a.last_system_update,
	a.last_user_update

FROM sys.dm_db_index_usage_stats a 
inner join sysindexes b 
	on a.object_id = b.id and a.index_id = b.indid

WHERE	object_name(a.object_id) = 'ProcOps'
		/*
			and	a.user_seeks	= 0 
			and a.user_lookups	= 0 
			and a.user_scans	= 0
			and a.index_id		> 1
		*/
		order by tamanho_mb desc