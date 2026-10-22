'use client';

import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import {
  UploadCloud,
  FileSearch,
  ShieldCheck,
  ArrowRight,
  LockKeyhole,
  X,
  Info,
} from 'lucide-react';

import { api, size } from '@/lib/api';
import { Button } from './ui/button';
import { ErrorBox } from './common';

export function UploadPage() {
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const config = useQuery({
    queryKey: ['settings'],
    queryFn: () => api('/api/settings'),
  });

  function select(f?: File) {
    setError(null);

    setFile(null);
    if (!f) return;

    if (!f.name.toLowerCase().endsWith('.exe')) {
      setError(new Error('Select a Windows .exe executable.'));
      return;
    }

    if (
      f.size >
      (config.data?.max_upload_mb || 32) * 1048576
    ) {
      setError(new Error('This file exceeds the configured upload limit.'));
      return;
    }

    setFile(f);
  }

  async function submit() {
    if (!file) return;

    setBusy(true);
    setError(null);

    const body = new FormData();

    body.append('file', file);
    body.append('external_consent', String(consent));

    try {
      const r = await api('/api/samples', {
        method: 'POST',
        body,
      });

      router.push('/analysis/' + r.analysis_id);
    } catch (e) {
      setError(e as Error);
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">NEW INVESTIGATION</div>

          <h1>Analyze an executable</h1>

          <p>
            Upload a sample. Follow the evidence from the first hash to the
            final verdict.
          </p>
        </div>
      </div>

      <div className="upload-layout">
        <section className="panel upload-panel">
          <div className="section-heading">
            <h2>Submit a sample</h2>

            <span className="badge gray">
              Windows executable
            </span>
          </div>

          <input
            ref={input}
            type="file"
            accept=".exe"
            className="sr-only"
            aria-label="Choose executable"
            onChange={(e) => select(e.target.files?.[0])}
          />

          <button
            className={`dropzone ${drag ? 'dragging' : ''}`}
            onClick={() => input.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setDrag(true);
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDrag(false);
              select(e.dataTransfer.files[0]);
            }}
            disabled={busy}
          >
            <span className="upload-circle">
              <UploadCloud size={34} />
            </span>

            <h2>Drop your executable here</h2>

            <p>
              or <span>browse files</span> to get started
            </p>

            <small>
              .EXE files only · Up to{' '}
              {config.data?.max_upload_mb || 32} MB
            </small>
          </button>

          {file && (
            <div className="selected-file">
              <FileSearch size={24} />

              <div>
                <strong>{file.name}</strong>

                <small>
                  {size(file.size)} · Ready for validation
                </small>
              </div>

              <button
                aria-label="Remove file"
                disabled={busy}
                onClick={() => setFile(null)}
              >
                <X size={18} />
              </button>
            </div>
          )}

          <div className="consent-box">
            <LockKeyhole size={19} />

            <div>
              <strong>Your sample, your control</strong>

              <p>
                Hash lookups may be sent to configured reputation services.
                The executable is analyzed by your local infrastructure.
              </p>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={consent}
                  disabled={!config.data?.external_uploads_enabled || busy}
                  onChange={(e) => setConsent(e.target.checked)}
                />

                <span>
                  Allow this file to be shared with external analysis
                  providers if a hash report is unavailable.
                </span>
              </label>

              {!config.data?.external_uploads_enabled && (
                <small>
                  External file uploads are disabled by administrator policy.
                </small>
              )}
            </div>
          </div>

          <ErrorBox error={error} />

          <div className="upload-actions">
            <span>
              <ShieldCheck size={15} />
              Isolated execution only
            </span>

            <Button
              disabled={!file || busy}
              onClick={submit}
            >
              {busy
                ? 'Uploading & validating…'
                : 'Start analysis'}

              <ArrowRight size={16} />
            </Button>
          </div>
        </section>

        <aside className="upload-aside">
          <div className="panel">
            <span className="mini-label">
              WHAT HAPPENS NEXT
            </span>

            <h2>A complete evidence trail</h2>

            {[
              [
                '01',
                'Validate & fingerprint',
                'Verify the file and calculate SHA-256, SHA-1, and MD5.',
              ],
              [
                '02',
                'Inspect & observe',
                'Run static rules, query reputation, and request isolated execution.',
              ],
              [
                '03',
                'Connect the evidence',
                'Correlate behavior, network activity, and AI indicators.',
              ],
              [
                '04',
                'Review the verdict',
                'Get a traceable report with explicit coverage gaps.',
              ],
            ].map(([n, t, d]) => (
              <div className="process-step" key={n}>
                <span>{n}</span>

                <div>
                  <strong>{t}</strong>

                  <p>{d}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="subtle-note">
            <Info size={18} />

            <p>
              Unavailable engines are clearly identified. An incomplete
              analysis is never treated as clean.
            </p>
          </div>
        </aside>
      </div>
    </>
  );
}