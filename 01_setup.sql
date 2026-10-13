-- =============================================================
-- 01_setup.sql
-- Create the compute warehouse, database, schema and raw table
-- =============================================================

-- Warehouse: the compute that runs queries.
-- XSMALL + AUTO_SUSPEND keeps costs minimal (pauses after 60s idle).
CREATE WAREHOUSE IF NOT EXISTS NETWORK_WH
  WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE;

CREATE DATABASE IF NOT EXISTS NETWORK_ANALYTICS;

-- RAW layer: data exactly as it arrives from the source
CREATE SCHEMA IF NOT EXISTS NETWORK_ANALYTICS.RAW;

USE WAREHOUSE NETWORK_WH;
USE SCHEMA NETWORK_ANALYTICS.RAW;

-- One row per network connection (flow)
CREATE OR REPLACE TABLE TRAFFIC_LOGS (
    flow_id         INTEGER,
    event_time      TIMESTAMP_NTZ,
    device_name     VARCHAR,
    src_ip          VARCHAR,
    src_port        INTEGER,
    dst_ip          VARCHAR,
    dst_port        INTEGER,
    protocol        VARCHAR,
    service         VARCHAR,
    bytes_sent      NUMBER,
    bytes_received  NUMBER,
    packets         INTEGER,
    duration_ms     INTEGER,
    action          VARCHAR      -- ALLOW / DENY (firewall decision)
);
