USE [ADM_BDADOS]
GO

/****** Object:  Table [dbo].[TB_PROCESS_DETAIL]    Script Date: 01/12/2021 21:46:51 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[TB_PROCESS_DETAIL](
	[collection_time] [datetime] NULL,
	[dd hh:mm:ss.mss] [varchar](20) NULL,
	[database_name] [nvarchar](128) NULL,
	[login_name] [nvarchar](128) NULL,
	[host_name] [nvarchar](128) NULL,
	[start_time] [datetime] NULL,
	[status] [varchar](30) NULL,
	[session_id] [int] NULL,
	[blocking_session_id] [int] NULL,
	[wait_info] [varchar](max) NULL,
	[open_tran_count] [int] NULL,
	[CPU] [varchar](max) NULL,
	[reads] [varchar](max) NULL,
	[writes] [varchar](max) NULL,
	[sql_command] [xml] NULL,
	[query_plan] [xml] NULL,
	[sql_text] [xml] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO


