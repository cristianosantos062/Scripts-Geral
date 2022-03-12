use master
go

if exists (select name from tempdb.sys.objects where name like '%#sp_lock%')
	drop procedure #sp_lock
go

create procedure #sp_lock
as

if exists (select name from tempdb.sys.objects where name like '%#tb_lock%')
	drop table #tb_lock


--> Sessões sendo bloqueadas
select 
	DB_NAME(er.database_id) dbname,
	er.session_id, er.status,
	er.blocking_session_id,
	er.wait_type,
	es.host_name,
	es.login_name,
	es.login_time,
	es.last_request_end_time,
	case convert(varchar(20), getdate() - er.start_time, 108)
          when '23:59:59' then '00:00:00'
          else convert(varchar(20), getdate() - er.start_time, 108)
    end as total_time, 
	er.command,
	OBJECT_NAME(st.objectid,er.database_id) [object_name],
	es.program_name,
	SubsTring(st.text,er.statement_start_offset/2, (Case When er.statement_end_offset = -1 Then Len(Convert(nVarChar(max), st.text))*2 
                                                                                                                  ELSE er.statement_end_offset
                                                                                                                  END 
       - er.statement_start_offset)/2) as TrechoQueryEmExecusao

into #tb_lock
from sys.dm_exec_requests er
Cross Apply sys.dm_exec_sql_text (er.sql_handle) st
Join sys.dm_exec_sessions es
on er.session_id = es.session_id
where er.session_id > 50 and er.blocking_session_id > 0

--> Sessões em execuções gerando bloqueio
insert into #tb_lock
select 
	DB_NAME(er.database_id) dbname,
	er.session_id, er.status,
	er.blocking_session_id,
	er.wait_type,
	es.host_name,
	es.login_name,
	es.login_time,
	es.last_request_end_time,
	case convert(varchar(20), getdate() - er.start_time, 108)
          when '23:59:59' then '00:00:00'
          else convert(varchar(20), getdate() - er.start_time, 108)
    end as total_time, 
	er.command,
	OBJECT_NAME(st.objectid,er.database_id) [object_name],
	es.program_name,
	SubsTring(st.text,er.statement_start_offset/2, (Case When er.statement_end_offset = -1 Then Len(Convert(nVarChar(max), st.text))*2 
                                                                                                                  ELSE er.statement_end_offset
                                                                                                                  END 
       - er.statement_start_offset)/2) as TrechoQueryEmExecusao

from sys.dm_exec_requests er
Cross Apply sys.dm_exec_sql_text (er.sql_handle) st
Join sys.dm_exec_sessions es on er.session_id = es.session_id
where er.session_id in (select distinct blocking_session_id from #tb_lock)
and er.blocking_session_id = 0

--> Sessões em sleeping gerando bloqueio
insert into #tb_lock
select 
	DB_NAME(es.database_id) dbname,
	es.session_id, 
	es.status,
	null,
	null,
	es.host_name,
	es.login_name,
	es.login_time,
	es.last_request_end_time,
	case convert(varchar(20), getdate() - es.last_request_end_time, 108)
          when '23:59:59' then '00:00:00'
          else convert(varchar(20), getdate() - es.last_request_end_time, 108)
    end as total_time, 
	-1,
	OBJECT_NAME(st.objectid,es.database_id) [object_name],
	es.program_name,
	st.text

from sys.dm_exec_sessions es with (nolock)
join sys.dm_exec_connections ec with (nolock) on es.session_id = ec.session_id
Cross Apply sys.dm_exec_sql_text (ec.most_recent_sql_handle) st
where es.session_id in  (select distinct blocking_session_id from #tb_lock with (nolock))
and es.session_id not in (select distinct session_id from #tb_lock with (nolock))


-->Lista árvore de bloqueios
select * from #tb_lock order by blocking_session_id asc

go
exec #sp_lock