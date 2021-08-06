use msdb
select 
	jh.job_id, 
	jh.step_id, 
	jh.step_name, 
	msdb.dbo.agent_datetime(jh.run_date, jh.run_time) RunDateTime,
	((run_duration/10000*3600 + (jh.run_duration/100)%100*60 + jh.run_duration%100 + 31 ) / 60) RunDurationMinutes,
	jh.run_status, 
	j.name,
	ja.last_executed_step_date,
	ja.start_execution_date,
	ja.stop_execution_date,
	DATEDIFF (minute, ja.start_execution_date, ja.stop_execution_date) tempo_exec,
	ja.next_scheduled_run_date
from sysjobhistory jh
	join sysjobs j on jh.job_id = j.job_id
	join sysjobactivity ja on jh.job_id = ja.job_id 
where ja.stop_execution_date > '2016-08-29'
order by tempo_exec desc