use master
go
select 
	object_name(est.objectid) Objeto,
	db_name (est.dbid),
	est.text,
	qs.plan_handle,
	eqp.query_plan,
	qs.creation_time,
	qs.last_execution_time,
	qs.last_elapsed_time,
	qs.min_elapsed_time,
	qs.max_elapsed_time,
	qs.execution_count
from sys.dm_exec_query_stats qs
	cross apply sys.dm_exec_sql_text(qs.sql_handle) est
	cross apply sys.dm_exec_query_plan (qs.plan_handle) eqp
where est.text like '%SET t.dt_atualizacaoRegistro = getdate()%'