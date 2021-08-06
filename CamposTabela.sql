use gi_gestaointegrada_sompo
SELECT distinct
		tb.name tabela, 
		col.name coluna, 
		tp.name,
		col.length 
	FROM sys.objects tb 
		inner join syscolumns col on (tb.object_id = col.id) 
		inner join systypes tp on (col.usertype = tp.usertype) 
	WHERE 
	--tb.name = 'T_ProcOPS'
	col.name like '%rede%'