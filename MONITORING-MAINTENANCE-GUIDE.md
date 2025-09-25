# RawrZ Security Platform - Monitoring & Maintenance Guide

## 📊 Monitoring Overview

The RawrZ Security Platform includes comprehensive monitoring and logging capabilities to ensure optimal performance and security.

## 🔍 Monitoring Stack

### Components
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Dashboards and visualization
- **Loki**: Log aggregation
- **Promtail**: Log shipping
- **Custom Health Checks**: Application-specific monitoring

### Access Points
- **Prometheus**: `http://YOUR_DROPLET_IP:9090`
- **Grafana**: `http://YOUR_DROPLET_IP:3001` (admin/admin123)
- **Loki**: `http://YOUR_DROPLET_IP:3100`
- **Application Health**: `http://YOUR_DROPLET_IP:3000/api/health`

## 📈 Key Metrics to Monitor

### Application Metrics
- **Response Time**: API endpoint response times
- **Error Rate**: 4xx and 5xx HTTP status codes
- **Throughput**: Requests per second
- **Active Connections**: Current user sessions
- **File Processing**: Upload/download rates
- **Engine Status**: Security engine health

### System Metrics
- **CPU Usage**: Per container CPU utilization
- **Memory Usage**: RAM consumption by service
- **Disk Usage**: Storage utilization
- **Network I/O**: Bandwidth usage
- **Database Performance**: Query times and connections
- **Redis Performance**: Cache hit rates

### Security Metrics
- **Failed Login Attempts**: Authentication failures
- **Suspicious Activity**: Unusual access patterns
- **File Uploads**: Malicious file detection
- **Engine Alerts**: Security engine warnings
- **System Intrusions**: Failed access attempts

## 🚨 Alerting Configuration

### Critical Alerts
```yaml
# High CPU Usage (>80%)
- alert: HighCPUUsage
  expr: rate(cpu_usage_total[5m]) > 0.8
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High CPU usage detected"

# High Memory Usage (>90%)
- alert: HighMemoryUsage
  expr: memory_usage_percent > 90
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High memory usage detected"

# Application Down
- alert: ApplicationDown
  expr: up{job="rawrz-app"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "RawrZ application is down"

# Database Connection Issues
- alert: DatabaseDown
  expr: up{job="postgres"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Database is down"

# High Error Rate
- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High error rate detected"
```

### Warning Alerts
```yaml
# Disk Space Low (<20%)
- alert: DiskSpaceLow
  expr: disk_usage_percent > 80
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Disk space is running low"

# Slow Response Time
- alert: SlowResponseTime
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Response time is slow"

# High File Upload Rate
- alert: HighFileUploadRate
  expr: rate(file_uploads_total[5m]) > 100
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Unusually high file upload rate"
```

## 📋 Daily Monitoring Checklist

### Morning Routine (5 minutes)
- [ ] Check Prometheus dashboard for any alerts
- [ ] Review Grafana dashboards for system health
- [ ] Verify all services are running: `docker-compose ps`
- [ ] Check application health: `curl http://localhost:3000/api/health`
- [ ] Review overnight logs for errors

### Health Check Commands
```bash
# Check all container status
docker-compose -f docker-compose.production.yml ps

# Check application health
curl -f http://localhost:3000/api/health

# Check database connectivity
docker-compose -f docker-compose.production.yml exec rawrz-db pg_isready -U rawrz_user -d rawrz_security

# Check Redis connectivity
docker-compose -f docker-compose.production.yml exec rawrz-redis redis-cli ping

# Check disk usage
df -h

# Check memory usage
free -h

# Check CPU usage
top -bn1 | grep "Cpu(s)"
```

## 🔧 Maintenance Tasks

### Weekly Maintenance (30 minutes)

#### 1. Log Rotation and Cleanup
```bash
# Clean old log files (older than 30 days)
find /opt/rawrz-platform/logs -name "*.log" -mtime +30 -delete

# Clean old backup files (older than 30 days)
find /opt/rawrz-platform/backups -name "*.sql" -mtime +30 -delete
find /opt/rawrz-platform/backups -name "*.tar.gz" -mtime +30 -delete

# Clean Docker system
docker system prune -f
docker volume prune -f
```

#### 2. Database Maintenance
```bash
# Connect to database
docker-compose -f docker-compose.production.yml exec rawrz-db psql -U rawrz_user -d rawrz_security

# Run database maintenance
VACUUM ANALYZE;
REINDEX DATABASE rawrz_security;

# Check database size
SELECT pg_size_pretty(pg_database_size('rawrz_security'));
```

#### 3. Security Updates
```bash
# Update system packages
apt update && apt upgrade -y

# Update Docker images
docker-compose -f docker-compose.production.yml pull

# Rebuild and restart services
docker-compose -f docker-compose.production.yml up -d --build
```

### Monthly Maintenance (2 hours)

#### 1. Performance Analysis
```bash
# Analyze slow queries
docker-compose -f docker-compose.production.yml exec rawrz-db psql -U rawrz_user -d rawrz_security -c "
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;"

# Check index usage
docker-compose -f docker-compose.production.yml exec rawrz-db psql -U rawrz_user -d rawrz_security -c "
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch 
FROM pg_stat_user_indexes 
ORDER BY idx_scan DESC;"
```

#### 2. Capacity Planning
```bash
# Check disk usage trends
du -sh /opt/rawrz-platform/*

# Check database growth
docker-compose -f docker-compose.production.yml exec rawrz-db psql -U rawrz_user -d rawrz_security -c "
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"

# Check log file sizes
find /opt/rawrz-platform/logs -name "*.log" -exec ls -lh {} \;
```

#### 3. Security Audit
```bash
# Check for failed login attempts
grep "Failed login" /opt/rawrz-platform/logs/app-*.log | tail -20

# Check for suspicious file uploads
grep "Suspicious file" /opt/rawrz-platform/logs/app-*.log | tail -20

# Review firewall logs
ufw status verbose

# Check SSL certificate expiration
openssl x509 -in /opt/rawrz-platform/nginx/ssl/rawrz.crt -noout -dates
```

## 🚨 Incident Response

### Service Outage Procedures

#### 1. Immediate Response (0-5 minutes)
```bash
# Check service status
docker-compose -f docker-compose.production.yml ps

# Check logs for errors
docker-compose -f docker-compose.production.yml logs --tail=100 rawrz-app

# Check system resources
htop
df -h
free -h

# Check network connectivity
ping 8.8.8.8
curl -I http://localhost:3000/api/health
```

#### 2. Service Recovery (5-15 minutes)
```bash
# Restart specific service
docker-compose -f docker-compose.production.yml restart rawrz-app

# Restart all services
docker-compose -f docker-compose.production.yml restart

# Rebuild and restart if needed
docker-compose -f docker-compose.production.yml up -d --build

# Check recovery
curl -f http://localhost:3000/api/health
```

#### 3. Root Cause Analysis (15+ minutes)
```bash
# Collect logs
docker-compose -f docker-compose.production.yml logs --since=1h > incident-logs-$(date +%Y%m%d-%H%M%S).txt

# Check system metrics
docker stats --no-stream > system-metrics-$(date +%Y%m%d-%H%M%S).txt

# Analyze database performance
docker-compose -f docker-compose.production.yml exec rawrz-db psql -U rawrz_user -d rawrz_security -c "
SELECT * FROM pg_stat_activity WHERE state = 'active';"
```

### Common Issues and Solutions

#### 1. High Memory Usage
```bash
# Check memory usage by container
docker stats --no-stream

# Restart high-memory containers
docker-compose -f docker-compose.production.yml restart rawrz-app

# Increase memory limits in docker-compose.production.yml
# Update memory limits and restart
docker-compose -f docker-compose.production.yml up -d
```

#### 2. Database Connection Issues
```bash
# Check database connections
docker-compose -f docker-compose.production.yml exec rawrz-db psql -U rawrz_user -d rawrz_security -c "
SELECT count(*) FROM pg_stat_activity;"

# Restart database
docker-compose -f docker-compose.production.yml restart rawrz-db

# Check database logs
docker-compose -f docker-compose.production.yml logs rawrz-db
```

#### 3. Disk Space Issues
```bash
# Check disk usage
df -h

# Clean up old files
docker system prune -a -f
find /opt/rawrz-platform/logs -name "*.log" -mtime +7 -delete

# Clean up old backups
find /opt/rawrz-platform/backups -name "*.sql" -mtime +30 -delete
```

## 📊 Performance Tuning

### Database Optimization
```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM your_slow_query;

-- Create indexes for frequently queried columns
CREATE INDEX CONCURRENTLY idx_table_column ON table_name (column_name);

-- Update table statistics
ANALYZE table_name;

-- Vacuum tables regularly
VACUUM ANALYZE table_name;
```

### Redis Optimization
```bash
# Check Redis memory usage
docker-compose -f docker-compose.production.yml exec rawrz-redis redis-cli info memory

# Monitor Redis performance
docker-compose -f docker-compose.production.yml exec rawrz-redis redis-cli monitor

# Flush cache if needed
docker-compose -f docker-compose.production.yml exec rawrz-redis redis-cli flushdb
```

### Application Optimization
```bash
# Check Node.js memory usage
docker-compose -f docker-compose.production.yml exec rawrz-app ps aux

# Monitor API response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:3000/api/health

# Check for memory leaks
docker-compose -f docker-compose.production.yml exec rawrz-app node --inspect=0.0.0.0:9229 api-server-no-cli.js
```

## 🔄 Backup and Recovery

### Automated Backups
```bash
# Check backup script
cat /opt/rawrz-platform/backup.sh

# Run manual backup
/opt/rawrz-platform/backup.sh

# Verify backup files
ls -la /opt/rawrz-platform/backups/
```

### Recovery Procedures
```bash
# Stop services
docker-compose -f docker-compose.production.yml down

# Restore database
docker-compose -f docker-compose.production.yml exec -T rawrz-db psql -U rawrz_user -d rawrz_security < /opt/rawrz-platform/backups/db_backup_YYYYMMDD_HHMMSS.sql

# Restore application data
tar -xzf /opt/rawrz-platform/backups/app_data_YYYYMMDD_HHMMSS.tar.gz

# Start services
docker-compose -f docker-compose.production.yml up -d
```

## 📈 Capacity Planning

### Growth Metrics
- **Daily Active Users**: Track user growth
- **File Upload Volume**: Monitor storage needs
- **API Request Volume**: Plan for scaling
- **Database Size**: Monitor growth trends
- **Log Volume**: Plan log retention

### Scaling Indicators
- **CPU Usage > 70%**: Consider horizontal scaling
- **Memory Usage > 80%**: Increase memory limits
- **Disk Usage > 85%**: Add storage or cleanup
- **Response Time > 2s**: Optimize or scale
- **Error Rate > 5%**: Investigate issues

### Scaling Actions
```bash
# Horizontal scaling (multiple instances)
docker-compose -f docker-compose.production.yml up -d --scale rawrz-app=3

# Vertical scaling (increase resources)
# Edit docker-compose.production.yml memory/CPU limits
docker-compose -f docker-compose.production.yml up -d

# Load balancer configuration
# Update nginx.conf for multiple upstream servers
docker-compose -f docker-compose.production.yml restart rawrz-nginx
```

## 🛡️ Security Monitoring

### Security Metrics
- **Failed Login Attempts**: Monitor authentication failures
- **Suspicious File Uploads**: Track malicious files
- **API Abuse**: Monitor unusual API usage patterns
- **System Intrusions**: Watch for unauthorized access
- **SSL Certificate Status**: Monitor certificate expiration

### Security Alerts
```bash
# Check failed login attempts
grep "Failed login" /opt/rawrz-platform/logs/app-*.log | wc -l

# Check suspicious file uploads
grep "Suspicious" /opt/rawrz-platform/logs/app-*.log

# Monitor API abuse
grep "Rate limit" /opt/rawrz-platform/logs/app-*.log

# Check SSL certificate
openssl x509 -in /opt/rawrz-platform/nginx/ssl/rawrz.crt -noout -dates
```

## 📞 Support and Escalation

### Monitoring Contacts
- **Primary Admin**: [Your Email]
- **Secondary Admin**: [Backup Email]
- **Emergency Contact**: [Phone Number]

### Escalation Procedures
1. **Level 1**: Automated alerts and self-healing
2. **Level 2**: Manual intervention and basic troubleshooting
3. **Level 3**: Advanced troubleshooting and vendor support
4. **Level 4**: Emergency procedures and disaster recovery

### Documentation Updates
- Update this guide monthly
- Document new procedures and issues
- Keep contact information current
- Review and update alerting rules

---

**Remember**: Proactive monitoring and maintenance prevent most issues. Regular health checks and performance analysis ensure optimal platform operation.