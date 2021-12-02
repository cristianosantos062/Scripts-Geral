EXEC [dbo].[sp_whoisactive]
	@not_filter = 'NT AUTHORITY\SYSTEM'				
	,@not_filter_type = 'login'	-- session, program, database, login, and host
	,@get_outer_command = 1
	,@get_plans = 1
    	,@get_locks = 1
	,@output_column_list = '[collection_time][dd hh:mm:ss.mss][database_name][login_name][host_name][start_time][status][session_id][blocking_session_id][wait_info][open_tran_count][CPU][reads][writes][sql_command][query_plan][sql_text]'
	,@destination_table = 'dbo.TB_PROCESS_DETAIL'


DELETE FROM dbo.TB_PROCESS_DETAIL WHERE collection_time < DATEADD(dd,-45,GETDATE())