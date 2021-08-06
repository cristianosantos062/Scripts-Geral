use funcional_sgs
go
declare @tabela varchar(100) = 'ProcOps',
		@indice varchar(100) = '[Index_CODPROCSGS_Nestle>]'
	select 
		OBJECT_NAME(ic.object_id) tabela,
		id.name indice,
		cl.name coluna,
		CAST((id.dpages* 8)/1024. AS numeric(17,2)) used_MB,
		case 
			when ic.is_included_column = 0 then 'Index_key'
			when ic.is_included_column = 1 then '(Include)'
		end as is_included
	from sys.index_columns ic
		join sys.columns cl on ic.column_id = cl.column_id and ic.object_id = cl.object_id
		join sysindexes id on ic.object_id = id.id and ic.index_id = id.indid
	where  object_name(ic.object_id)= @tabela and id.name = @indice