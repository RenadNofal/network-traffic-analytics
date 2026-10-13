-- =============================================================
-- 04_analytics_views.sql
-- ANALYTICS layer: reusable views that power the dashboard
-- =============================================================

USE WAREHOUSE NETWORK_WH;
CREATE SCHEMA IF NOT EXISTS NETWORK_ANALYTICS.ANALYTICS;
USE SCHEMA NETWORK_ANALYTICS.ANALYTICS;

-- Devices ranked by data volume
CREATE OR REPLACE VIEW V_TOP_TALKERS AS
SELECT
    device_name,
    src_ip,
    COUNT(*)                                                  AS connections,
    ROUND(SUM(bytes_sent)     / 1024 / 1024, 1)               AS mb_sent,
    ROUND(SUM(bytes_received) / 1024 / 1024, 1)               AS mb_received,
    ROUND(SUM(bytes_sent + bytes_received) / 1024 / 1024, 1)  AS total_mb
FROM NETWORK_ANALYTICS.RAW.TRAFFIC_LOGS
GROUP BY device_name, src_ip;

-- Traffic volume per hour (for spotting peaks)
CREATE OR REPLACE VIEW V_HOURLY_TRAFFIC AS
SELECT
    DATE_TRUNC('hour', event_time)                            AS hour,
    DAYNAME(event_time)                                       AS day_name,
    COUNT(*)                                                  AS connections,
    ROUND(SUM(bytes_sent + bytes_received) / 1024 / 1024, 1)  AS total_mb
FROM NETWORK_ANALYTICS.RAW.TRAFFIC_LOGS
GROUP BY hour, day_name;

-- Traffic and firewall denials per service
CREATE OR REPLACE VIEW V_SERVICE_BREAKDOWN AS
SELECT
    service,
    COUNT(*)                                                  AS connections,
    ROUND(SUM(bytes_sent + bytes_received) / 1024 / 1024, 1)  AS total_mb,
    SUM(IFF(action = 'DENY', 1, 0))                           AS denied
FROM NETWORK_ANALYTICS.RAW.TRAFFIC_LOGS
GROUP BY service;

-- Detection rule: a device hitting 50+ distinct ports on one target
-- within one hour is flagged as a possible port scan
CREATE OR REPLACE VIEW V_PORT_SCAN_ALERTS AS
SELECT
    device_name,
    src_ip,
    dst_ip,
    DATE_TRUNC('hour', event_time)  AS hour,
    COUNT(DISTINCT dst_port)        AS ports_tried,
    SUM(IFF(action = 'DENY', 1, 0)) AS denied,
    MIN(event_time)                 AS first_seen,
    MAX(event_time)                 AS last_seen
FROM NETWORK_ANALYTICS.RAW.TRAFFIC_LOGS
GROUP BY device_name, src_ip, dst_ip, hour
HAVING COUNT(DISTINCT dst_port) >= 50;

-- Quick checks
SELECT * FROM V_TOP_TALKERS ORDER BY total_mb DESC;
SELECT * FROM V_SERVICE_BREAKDOWN ORDER BY connections DESC;
SELECT * FROM V_PORT_SCAN_ALERTS;
