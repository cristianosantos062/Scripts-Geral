	select top 10
		db_name(qp.dbid) dbname,
		object_name(qp.objectid, qp.dbid) procname,
		st.text,
		qp.query_plan,
		ps.last_execution_time,
		total_logical_reads / execution_count as avg_logical_reads,
		total_logical_writes / execution_count as avg_logical_writes,
		total_physical_reads / execution_count as avg_physical_reads,
		ps.execution_count
	from sys.dm_exec_query_stats ps
		cross apply sys.dm_exec_query_plan(ps.plan_handle) qp
		cross apply sys.dm_exec_sql_text (ps.sql_handle) st
	order by
	avg_physical_reads desc