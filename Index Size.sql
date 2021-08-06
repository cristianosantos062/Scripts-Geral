
SELECT
OBJECT_NAME(i.OBJECT_ID) AS TableName,
i.name AS IndexName,
i.index_id AS IndexID,
8 * SUM(a.used_pages)/1024 AS 'Indexsize(MB)',i.type_desc
FROM sys.indexes AS i
JOIN sys.partitions AS p ON p.OBJECT_ID = i.OBJECT_ID AND p.index_id = i.index_id
JOIN sys.allocation_units AS a ON a.container_id = p.partition_id
--WHERE name in ('Data_index_Pre_aut_itens','index_tpl_data','Index_data')
GROUP BY i.OBJECT_ID,i.index_id,i.name,i.type_desc
ORDER BY 'Indexsize(MB)'desc ,OBJECT_NAME(i.OBJECT_ID),i.index_id








