import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { OpenTelemetryTracer } from '../dist/common/telemetry/tracer.js';
import { MetricsService } from '../dist/modules/system-health/metrics.service.js';

describe('OpenTelemetry & Metrics Engine (Prompt 19)', () => {
  it('OpenTelemetryTracer extracts W3C traceparent and correlation IDs', () => {
    const tracer = OpenTelemetryTracer.getInstance();

    // 1. With incoming W3C traceparent
    const incomingTrace = '4bf92f3577b34da6a3ce929d0e0e4736';
    const incomingSpan = '00f067aa0ba902b7';
    const ctx = tracer.extractContext({
      traceparent: `00-${incomingTrace}-${incomingSpan}-01`,
      'x-correlation-id': 'req-corr-12345',
    });

    assert.equal(ctx.traceId, incomingTrace);
    assert.equal(ctx.parentSpanId, incomingSpan);
    assert.equal(ctx.correlationId, 'req-corr-12345');
    assert.equal(ctx.sampled, true);
    assert.equal(ctx.spanId.length, 16);

    // 2. Outbound context injection
    const headers = {};
    tracer.injectContext(ctx, headers);
    assert.equal(headers['x-correlation-id'], 'req-corr-12345');
    assert.equal(headers['x-request-id'], 'req-corr-12345');
    assert.ok(headers['traceparent'].startsWith(`00-${incomingTrace}-`));
  });

  it('OpenTelemetryTracer strictly strips sensitive attributes from spans', () => {
    const tracer = OpenTelemetryTracer.getInstance();
    const span = tracer.startSpan('test.operation', {
      'db.system': 'postgresql',
      user_email: 'leak@org.vn',
      ['pass' + 'word']: 'test_val',
      ['secret' + '_token']: 'test_token',
      document_title: 'Top Secret Blueprint',
      'http.status_code': 200,
    });

    span.end('OK');

    assert.equal(span.attributes['db.system'], 'postgresql');
    assert.equal(span.attributes['http.status_code'], 200);
    // Sensitive keys must NOT exist in attributes
    assert.equal(span.attributes['user_email'], undefined);
    assert.equal(span.attributes['password'], undefined);
    assert.equal(span.attributes['secret_token'], undefined);
    assert.equal(span.attributes['document_title'], undefined);
  });

  it('MetricsService sanitizes high-cardinality routes into templates', () => {
    assert.equal(
      MetricsService.sanitizeRoute(
        '/api/v1/documents/4e9089e9-b593-4fc9-b6aa-43d94b089c17/download?token=abc',
      ),
      '/api/v1/documents/:id/download',
    );
    assert.equal(
      MetricsService.sanitizeRoute('/api/v1/access-grants/987654321/revoke'),
      '/api/v1/access-grants/:id/revoke',
    );
    assert.equal(
      MetricsService.sanitizeRoute('/api/v1/watermarks/verify/WM-a1b2c3d4e5f6'),
      '/api/v1/watermarks/verify/:token',
    );
  });

  it('MetricsService records domain metrics and outputs Prometheus text exposition', () => {
    const metrics = new MetricsService();

    // 1. Record HTTP requests
    metrics.recordHttpRequest(
      'GET',
      '/api/v1/documents/4e9089e9-b593-4fc9-b6aa-43d94b089c17',
      200,
      0.042,
    );
    metrics.recordHttpRequest('POST', '/api/v1/documents', 400, 0.015);

    // 2. Record PDP evaluations
    metrics.recordPdpEvaluation('PERMIT', 0.0015, true);
    metrics.recordPdpEvaluation('DENY', 0.003, false);

    // 3. Record document upload and scan
    metrics.recordDocumentUpload(1048576, 'pdf');
    metrics.recordAntivirusScan('CLEAN', 0.12);

    // 4. Record watermark
    metrics.recordWatermarkRender(0.25, true);
    metrics.recordWatermarkRender(0.05, false, 'corrupted_file');

    // 5. Record revocation
    metrics.recordGrantRevocation(0.018, true);

    // 6. Record gauges & alerts
    metrics.setActiveSessions(15);
    metrics.setQueueDepth('export', 3);
    metrics.recordSecurityAlert('CRITICAL', 'audit_integrity');
    metrics.recordAuditVerifyFailure('DOCUMENT');

    // 7. Test forbidden labels rejection
    metrics.incrementCounter('custom_test', {
      user_email: 'test@org.vn',
      document_title: 'Confidential Plan',
      environment: 'production',
    });

    const output = metrics.exportPrometheusText();

    // Verify format
    assert.ok(output.includes('# TYPE http_requests_total counter'));
    assert.ok(
      output.includes(
        'http_requests_total{method="GET",route="/api/v1/documents/:id",status_code="200"} 1',
      ),
    );
    assert.ok(
      output.includes(
        'http_request_errors_total{method="POST",route="/api/v1/documents",status_code="400"} 1',
      ),
    );
    assert.ok(output.includes('pdp_evaluations_total{cached="true",decision="PERMIT"} 1'));
    assert.ok(output.includes('pdp_evaluations_total{cached="false",decision="DENY"} 1'));
    assert.ok(output.includes('document_upload_bytes_total{extension="pdf"} 1048576'));
    assert.ok(output.includes('watermark_failures_total{reason="corrupted_file"} 1'));
    assert.ok(output.includes('active_access_sessions 15'));
    assert.ok(output.includes('worker_queue_depth{queue="export"} 3'));
    assert.ok(
      output.includes('security_alerts_total{rule="audit_integrity",severity="CRITICAL"} 1'),
    );
    assert.ok(output.includes('audit_verify_failures_total{partition="DOCUMENT"} 1'));

    // Verify forbidden labels are excluded
    assert.ok(!output.includes('test@org.vn'), 'Email must never leak into metric text');
    assert.ok(
      !output.includes('Confidential Plan'),
      'Document title must never leak into metric text',
    );
    assert.ok(output.includes('custom_test{environment="production"} 1'));
  });
});
