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
import {discardUpload,uploadFile,UploadProgress} from '@/lib/upload';
import { Button } from './ui/button';
import { ErrorBox } from './common';

export function UploadPage() {
  const router = useRouter();
  const input = useRef<HTMLInputElement>(null);
  const controller = useRef<AbortController|null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [progress,setProgress]=useState<UploadProgress|null>(null);
  const [session,setSession]=useState<string|null>(null);
  const [paused,setPaused]=useState(false);
  const [softwareName,setSoftwareName]=useState(''),[softwareVersion,setSoftwareVersion]=useState('');

  const config = useQuery({
    queryKey: ['settings'],
    queryFn: () => api('/api/settings'),
  });

  function select(f?: File) {
    if(busy)return;
    setError(null);
    setProgress(null);setSession(null);setPaused(false);

    setFile(null);
    if (!f) return;

    if (!f.name.toLowerCase().endsWith('.exe')) {
      setError(new Error('Select a Windows .exe executable.'));
      return;
    }

    if (
      f.size >
      (config.data?.max_upload_mb || 2048) * 1048576
    ) {
      setError(new Error('This file exceeds the configured upload limit.'));
      return;
    }
    if(f.size<64){setError(new Error('The file is too small to be a Windows executable.'));return;}

    setFile(f);
  }

  async function submit() {
    if (!file) return;
    if(Boolean(softwareName.trim())!==Boolean(softwareVersion.trim())){setError(new Error('Enter both software name and version, or leave both empty for automatic detection.'));return;}

    setBusy(true);
    setError(null);
    setPaused(false);
    const current=new AbortController();controller.current=current;

    try {
      const identifier=await uploadFile(file,consent,current.signal,setProgress,setSession,softwareName.trim()?{name:softwareName.trim(),version:softwareVersion.trim()}:undefined);
      router.push('/analysis/' + identifier);
    } catch (e) {
      if(current.signal.aborted)setPaused(true);else setError(e instanceof Error?e:new Error('Upload failed'));
      setBusy(false);
    }
  }

  async function discard(){if(!session)return;setBusy(true);setError(null);try{await discardUpload(session);setSession(null);setProgress(null);setPaused(false)}catch(e){setError(e as Error)}finally{setBusy(false)}}

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
            disabled={busy}
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
              {size((config.data?.max_upload_mb || 2048)*1048576)}
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

          <div className="software-identity-form">
            <h3>Software vulnerability lookup</h3>
            <p>Product name and version are detected from the executable. Enter them here if they are missing or need correcting.</p>
            <div><label>Software name<input value={softwareName} onChange={e=>setSoftwareName(e.target.value)} placeholder="e.g. 7-Zip" maxLength={160} disabled={busy||!!session}/></label><label>Software version<input value={softwareVersion} onChange={e=>setSoftwareVersion(e.target.value)} placeholder="e.g. 16.00" maxLength={128} disabled={busy||!!session}/></label></div>
            <small>Published product/version advisories are checked automatically. Name and version may be sent to advisory providers.</small>
          </div>

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
          {progress&&<div className="upload-progress" aria-live="polite">
            <p><strong>{paused?'Upload paused':progress.phase==='hashing'?'Checking file fingerprint':progress.phase==='finalizing'?'Validating and saving file':'Uploading file'}</strong>{progress.resumed?' · Resumed from saved chunks':''}</p>
            <div className="progress-track" role="progressbar" aria-label={progress.phase==='hashing'?'File fingerprint progress':'Upload progress'} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress.bytes/progress.total*100)}><div style={{width:`${progress.bytes/progress.total*100}%`}}/></div>
            <p>{size(progress.bytes)} / {size(progress.total)}{progress.bytesPerSecond>0&&!paused?` · ${size(progress.bytesPerSecond)}/s`:''}</p>
          </div>}
          {(paused||error)&&session&&<p>Choose the same file and retry to resume. Inactive upload chunks expire after one hour.</p>}

          <div className="upload-actions">
            <span>
              <ShieldCheck size={15} />
              Isolated execution only
            </span>

            {busy&&progress?.phase!=='finalizing'&&<Button variant="outline" onClick={()=>controller.current?.abort()}>Pause</Button>}
            {!busy&&session&&<Button variant="outline" onClick={discard}>Discard upload</Button>}

            <Button
              disabled={!file || busy}
              onClick={submit}
            >
              {busy
                ? progress?.phase==='finalizing'?'Validating file…':'Preparing upload…'
                : session?'Resume analysis':'Start analysis'}

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
                'Identify software and version, check published vulnerabilities, and run static and reputation checks.',
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
              analysis is never treated as clean. Files and reports are retained for 7 days. Uploads resume after temporary connection failures.
            </p>
          </div>
        </aside>
      </div>
    </>
  );
}
