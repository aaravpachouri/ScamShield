
import type { ApiHealth, SourceMode, AnalyzeResponse } from '../types';

const API_BASE = (
  import.meta.env.VITE_SCAMSHIELD_API_URL ||
  (window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1'
    ? 'http://127.0.0.1:8000'
    : `http://${window.location.hostname}:8000`)
).replace(/\/$/, '');

const REQUEST_TIMEOUT_MS = 120_000;

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit = {}
): Promise<Response> {
  const controller = new AbortController();

  const timeout = window.setTimeout(
    () => controller.abort(),
    REQUEST_TIMEOUT_MS
  );

  try {
    return await fetch(input, {
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error(
        'The analysis took too long. Check the API connection and try again.'
      );
    }

    throw new Error(
      `Could not reach the ScamShield API at ${API_BASE}. Check the API URL and your network connection.`
    );
  } finally {
    window.clearTimeout(timeout);
  }
}

async function readError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as {
      detail?: unknown;
      message?: unknown;
    };

    if (typeof body.detail === 'string') return body.detail;
    if (typeof body.message === 'string') return body.message;
  } catch {
    // Handle non-JSON responses below.
  }

  return `Request failed (${response.status} ${response.statusText || 'HTTP error'}).`;
}

export async function getHealth(): Promise<ApiHealth> {
  const response = await fetchWithTimeout(`${API_BASE}/api/health`);

  if (!response.ok) throw new Error(await readError(response));

  return response.json() as Promise<ApiHealth>;
}

export async function analyzeText(
  text: string,
  sourceMode: Exclude<SourceMode, 'Screenshot'>
): Promise<AnalyzeResponse> {
  const response = await fetchWithTimeout(`${API_BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, source_mode: sourceMode }),
  });

  if (!response.ok) throw new Error(await readError(response));

  const data = (await response.json()) as AnalyzeResponse;

  if (!data?.success || !data.result) {
    throw new Error('The API returned an unexpected analysis response.');
  }

  return data;
}

export async function analyzeScreenshot(file: File): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append('file', file);

  const response = await fetchWithTimeout(
    `${API_BASE}/api/analyze-screenshot`,
    { method: 'POST', body: form }
  );

  if (!response.ok) throw new Error(await readError(response));

  const data = (await response.json()) as AnalyzeResponse;

  if (!data?.success || !data.result) {
    throw new Error('The API returned an unexpected screenshot-analysis response.');
  }

  return data;
}

export function getApiBase(): string {
  return API_BASE;
}
