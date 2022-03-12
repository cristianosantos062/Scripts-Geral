

if exists (select name from tempdb.sys.objects where name like '%p_processes_details%')
	drop procedure #p_processes_details

go
create procedure #p_processes_details 
	(@session_id nvarchar(4), @dbname nvarchar(100), @geral int, @trechoexecucao int)


as

declare @t_sql nvarchar(max) = '
      select      req.session_id,
                  blocking_session_id,    
                  db_name(req.database_id) dbname,
				   OBJECT_NAME(st.objectid,req.database_id) [object_name],
                  ses.login_time,
                  ses.last_request_end_time,                
                  case convert(varchar(20), getdate() - req.start_time, 108) 
                        when ''23:59:59'' then ''00:00:00''
                        else convert(varchar(20), getdate() - req.start_time, 108)
                  end as total_time,                  
                  req.cpu_time,
				  req.reads,
                  req.writes,
                  req.logical_reads,
				  req.wait_time,
                  req.wait_type,
                  req.wait_resource,
                  mmg.dop as QueryDOP,                
                  (select COUNT(*) from sys.dm_os_tasks tsk2 where tsk2.session_id = req.session_id) as taskcount,                         
                  mmg.query_cost,
				  (select query_plan from sys.dm_exec_query_plan (req.plan_handle)) as query_plan,
				  mmg.requested_memory_kb,
                  (SELECT SUBSTRING(st.text,req.statement_start_offset/2,(CASE WHEN req.statement_end_offset = -1 then LEN(CONVERT(nvarchar(max), text)) * 2 ELSE req.statement_end_offset end -req.statement_start_offset)/2) FROM sys.dm_exec_sql_text(req.sql_handle)) [actual_text], 
                  ses.host_name,
                  ses.login_name,
                  req.status,
                  req.command,
                  req.last_wait_type,
                  ses.program_name, 
                  req.start_time, 
                  req.status,
                  req.command,            
                  ses.last_request_start_time,
                  ses.last_request_end_time,
                  ses.login_name,
                  req.open_transaction_count,
                  req.open_resultset_count,
                  req.percent_complete,
                  req.estimated_completion_time,
				  req.plan_handle
                  from sys.dm_exec_requests req with(nolock)
				    CROSS APPLY sys.dm_exec_sql_text (req.sql_handle) st
				  inner join sys.dm_exec_sessions ses with(nolock)
                              on req.session_id = ses.session_id
                        left join sys.dm_exec_query_memory_grants mmg with(nolock)
                              on req.session_id = mmg.session_id '

, @t_sql_filtro_padrao  nvarchar(max) = ' where req.session_id > 50 and req.session_id <> @@SPID'
, @t_sql_filtro_sessioid  nvarchar(max) = ' where req.session_id =''' + @session_id + ''''
, @t_sql_filtro_dbname  nvarchar(max) = ' where req.session_id > 50 and req.session_id <> @@SPID and db_name(req.database_id) =''' + @dbname + ''''
, @t_sql_ordenacao  nvarchar(max) = ' order by 7 desc, 9 desc'

, @t_sql_trecho  nvarchar(max) = 'select req.session_id,
									db_name(req.database_id) dbname,
								       st.text as TSQLCompleto,
								       qp.query_plan as PlanoCompleto,
								       SubsTring(st.text,req.statement_start_offset/2, (Case When req.statement_end_offset = -1 Then Len(Convert(nVarChar(max), st.text))*2
								                                                                                                                  ELSE req.statement_end_offset
								                                                                                                                  END
								       - req.statement_start_offset)/2) as TrechoQueryEmExecusao,
								       CAST(tpq.query_plan as XML) as TrechoPlanoEmExecusao
								from sys.dm_exec_requests req
									Cross apply sys.dm_exec_text_query_plan(req.plan_handle, req.statement_start_offset , req.statement_end_offset) tpq
									Cross apply sys.dm_exec_query_plan (req.plan_handle) qp
									Cross Apply sys.dm_exec_sql_text (req.sql_handle) st '
, @t_sql_ordenacao_trecho  nvarchar(max) = ' order by 1 asc'			  
--, @t_sql_filtro_sessioid_trecho  nvarchar(max) = ' order by 1 asc'		
--, @t_sql_filtro_dbname_trecho  nvarchar(max) = ' order by 1 asc'		



	
if  @geral = 1
begin 

	if  @session_id is not null
	begin 
		set @t_sql = @t_sql + @t_sql_filtro_sessioid + @t_sql_ordenacao
		exec sp_executesql @t_sql
	end
	
	if  @dbname  is not null
	begin 
		set @t_sql = @t_sql + @t_sql_filtro_dbname + @t_sql_ordenacao
		exec sp_executesql @t_sql
	end

	if  @session_id is null and @dbname is null
	begin
		set @t_sql = @t_sql + @t_sql_filtro_padrao + @t_sql_ordenacao
		exec sp_executesql @t_sql
	end
end


if @trechoexecucao = 1
begin 
	if  @session_id is not null
	begin 
		set @t_sql_trecho = @t_sql_trecho + @t_sql_filtro_sessioid + @t_sql_ordenacao_trecho
		exec sp_executesql @t_sql_trecho
	end
	
	if  @dbname  is not null
	begin 
		set @t_sql_trecho = @t_sql_trecho + @t_sql_filtro_dbname + @t_sql_ordenacao_trecho
		exec sp_executesql @t_sql_trecho
	end
	
	if @session_id is null and @dbname  is null
	begin
		set @t_sql_trecho = @t_sql_trecho + @t_sql_filtro_padrao + @t_sql_ordenacao_trecho
		exec sp_executesql @t_sql_trecho
	end
end

go

exec #p_processes_details      
	  @session_id 	  = null   
	, @dbname 		  = null   
	, @geral 		  = 1      
	, @trechoexecucao = 1


	sp_Readerrorlog