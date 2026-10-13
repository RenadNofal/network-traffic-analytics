-- =============================================================
-- 02_load_data.sql
-- Load the CSV: file -> internal stage -> COPY INTO table
-- =============================================================

USE WAREHOUSE NETWORK_WH;
USE SCHEMA NETWORK_ANALYTICS.RAW;

-- How to parse the CSV
CREATE OR REPLACE FILE FORMAT CSV_FORMAT
  TYPE = 'CSV'
  SKIP_HEADER = 1
  FIELD_OPTIONALLY_ENCLOSED_BY = '"';

-- Internal stage: landing area for files before they are loaded
CREATE OR REPLACE STAGE TRAFFIC_STAGE
  FILE_FORMAT = CSV_FORMAT
  DIRECTORY = (ENABLE = TRUE);

-- Upload data/network_traffic_logs.csv to the stage
-- (Snowsight: Catalog > NETWORK_ANALYTICS > RAW > Stages > TRAFFIC_STAGE > + Files)
-- or with SnowSQL:  PUT file://data/network_traffic_logs.csv @TRAFFIC_STAGE;

LIST @TRAFFIC_STAGE;

COPY INTO TRAFFIC_LOGS
FROM @TRAFFIC_STAGE
FILE_FORMAT = (FORMAT_NAME = CSV_FORMAT);

-- Validate: expect 29,489 rows
SELECT COUNT(*) FROM TRAFFIC_LOGS;
SELECT * FROM TRAFFIC_LOGS LIMIT 10;
