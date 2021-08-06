	select top 10
		db_name(ps.database_id) dbname,
		object_name(ps.object_id, ps.database_id) procname,
		st.text,
		qp.query_plan,
		ps.last_execution_time,
		total_logical_reads / execution_count as avg_logical_reads,
		total_logical_writes / execution_count as avg_logical_writes,
		total_physical_reads / execution_count as avg_physical_reads 
	from sys.dm_exec_procedure_stats ps
		cross apply sys.dm_exec_query_plan(ps.plan_handle) qp
		cross apply sys.dm_exec_sql_text (ps.sql_handle) st
	order by 
	avg_physical_reads desc