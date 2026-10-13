-- =============================================================
-- 03_exploration.sql
-- Exploratory analysis that led to the findings in the README
-- =============================================================

USE WAREHOUSE NETWORK_WH;
USE SCHEMA NETWORK_ANALYTICS.RAW;

-- Q1. Top talkers: which devices send/receive the most data?
SELECT
    device_name,
    COUNT(*)                                                  AS connections,
    ROUND(SUM(bytes_sent)     / 1024 / 1024, 1)               AS mb_sent,
    ROUND(SUM(bytes_received) / 1024 / 1024, 1)               AS mb_received,
    ROUND(SUM(bytes_sent + bytes_received) / 1024 / 1024, 1)  AS total_mb
FROM TRAFFIC_LOGS
GROUP BY device_name
ORDER BY total_mb DESC
LIMIT 10;

-- Q2. When is the network busiest?
SELECT
    HOUR(event_time) AS hour_of_day,
    COUNT(*)         AS connections
FROM TRAFFIC_LOGS
GROUP BY hour_of_day
ORDER BY hour_of_day;

-- Q3. Which device was blocked by the firewall most often?
SELECT
    device_name,
    COUNT(*) AS connections
FROM TRAFFIC_LOGS
WHERE action = 'DENY'
GROUP BY device_name
ORDER BY connections DESC;

-- Q4. Investigate the outlier (LAPTOP-13): what was it targeting?
SELECT
    dst_ip,
    COUNT(*)                 AS attempts,
    COUNT(DISTINCT dst_port) AS different_ports_tried,
    MIN(dst_port)            AS lowest_port,
    MAX(dst_port)            AS highest_port,
    MIN(event_time)          AS first_attempt,
    MAX(event_time)          AS last_attempt
FROM TRAFFIC_LOGS
WHERE device_name = 'LAPTOP-13'
  AND action = 'DENY'
GROUP BY dst_ip
ORDER BY attempts DESC;
