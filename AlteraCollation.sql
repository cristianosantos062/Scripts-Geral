select * from sys.databases
-- SQL_Latin1_General_CP1_CI_AS
-- Latin1_General_CI_AS

use AdventureWorks
select c.name coluna,
t.name tabela,
c.collation_name
from sys.columns c
join sys.tables t on c.object_id = t.object_id
where collation_name is not null
and t.type = 'u'
order by 2

use master

alter database AdventureWorks set single_user with rollback immediate
go
alter database AdventureWorks collate Latin1_General_CI_AS
go
alter database AdventureWorks set multi_user with rollback immediate

select * from sys.databases
SQL_Latin1_General_CP1_CI_AS

select 'ALTER TABLE [' + t.name + '] ALTER COLUMN [' + c.name + '] ' +  ty.name + ' (' + CONVERT(varchar, c.max_length) + ') COLLATE Latin1_General_CI_AS NULL'
from sys.columns c
inner join sys.tables t on c.object_id = t.object_id
inner join sys.types as ty on ty.system_type_id = c.system_type_id
where c.collation_name is not null and c.collation_name <> 'Latin1_General_CI_AS'
and t.type = 'u'


