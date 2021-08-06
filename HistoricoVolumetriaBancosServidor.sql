;with volumetria as
(
	select 
		database_name,
		File_Size_in_MB,
		Space_Used_in_MB,
		space_left_in_MB,
		Polldate
	from [dbo].[db_file_info]
	where file_id = 1 
	and Polldate > '2016-01-01'
	and Database_Name not in ('master', 'msdb', 'model', 'tempdb')
)

select 
	vt.database_name,
	vt.File_Size_in_MB EspacoAlocado_Dados,
	vt.Space_Used_in_MB EspacoUtilizado_Dados,
	vt.space_left_in_MB EspacoLivre_Dados,
	dfi.File_Size_in_MB EspacoLog,
	vt.Polldate 
from [dbo].[db_file_info] dfi
 inner join volumetria vt
 on dfi.Database_Name = vt.Database_Name and cast (dfi.Polldate as date) = cast (vt.polldate as date)
 where dfi.file_id = 2
-- and vt.database_name = 'DW_GestaoIntegrada_DorConsultoria'
 
 order by dfi.polldate desc
