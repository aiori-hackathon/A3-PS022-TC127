#!/usr/bin/env python3
"""Read-only release checks: references, evidence hashes, core hashes and PDF."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[2]


def sha(data): return hashlib.sha256(data).hexdigest()


def main():
    errors=[]
    checked_links=0
    docs=[ROOT/'README.md',ROOT/'src/README.md']+list((ROOT/'docs').glob('*.md'))+list((ROOT/'reports').rglob('*.md'))
    for path in docs:
        if '.build' in path.parts: continue
        text=path.read_text()
        for target in re.findall(r'\]\(([^)]+)\)',text):
            target=target.strip('<>').split(' "')[0]
            if re.match(r'\w+://',target) or target.startswith('#'): continue
            relative=target.split('#')[0]
            if relative and not (path.parent/relative).exists():
                errors.append(f'Broken relative link: {path.relative_to(ROOT)} -> {target}')
            checked_links+=1
    evidence=ROOT/'reports/evidence'
    manifest=json.loads((evidence/'artifact-manifest.json').read_text())
    analysis=json.loads((evidence/'analysis.json').read_text())
    archive_path=evidence/'raw-benchmarks.tar.gz'
    if sha(archive_path.read_bytes())!=analysis['archive_sha256']: errors.append('Archive checksum mismatch')
    local_checked=0
    with tarfile.open(archive_path,'r:gz') as archive:
        for item in manifest:
            raw=archive.extractfile(item['path']).read()
            if len(raw)!=item['bytes'] or sha(raw)!=item['sha256']: errors.append('Archive artifact mismatch: '+item['path'])
            local=ROOT/'build/bench'/item['path']
            if local.exists():
                local_checked+=1
                if sha(local.read_bytes())!=item['sha256']: errors.append('Local evidence changed: '+item['path'])
    provenance=json.loads((ROOT/'reports/source/provenance.json').read_text())
    for name,expected in provenance['protected_core_sha256'].items():
        if sha((ROOT/name).read_bytes())!=expected:errors.append('Protected source changed: '+name)
    pdf=ROOT/'reports/ByteGuard_Technical_Report.pdf'
    reader=PdfReader(pdf)
    page_lengths=[]
    for index,page in enumerate(reader.pages,1):
        text=page.extract_text() or ''
        page_lengths.append(len(text))
        if len(text)<450: errors.append(f'Empty/nearly empty PDF page {index}')
        if f'Page {index}' not in text:errors.append(f'Missing footer on page {index}')
        if abs(float(page.mediabox.width)-595.276)>.1 or abs(float(page.mediabox.height)-841.89)>.1:
            errors.append(f'Unexpected page size {index}')
    all_text='\n'.join(page.extract_text() or '' for page in reader.pages)
    for heading in ('1. Problem Description','8. Performance Evaluation','12. Proposed Improvements',
                    '14. References','Appendix A.','Appendix B.','Appendix C.'):
        if heading not in all_text:errors.append('Missing section: '+heading)
    if 'not implemented in the current ByteGuard baseline' not in all_text:
        errors.append('Future diagram implementation disclaimer missing')
    # Poppler word bounds supplement, but do not replace, page-by-page inspection.
    bbox=subprocess.run(['pdftotext','-bbox',str(pdf),'-'],text=True,capture_output=True,check=True).stdout
    tree=ET.fromstring(bbox)
    margin_warnings=[]
    for number,page in enumerate(tree.findall('.//{*}page'),1):
        for word in page.findall('.//{*}word'):
            if float(word.get('xMin'))<70 or float(word.get('xMax'))>525:
                margin_warnings.append({'page':number,'word':word.text,'xMin':word.get('xMin'),'xMax':word.get('xMax')})
    result={'pdf_pages':len(reader.pages),'pdf_sha256':sha(pdf.read_bytes()),'local_links_checked':checked_links,
            'archived_artifacts_checked':len(manifest),'local_artifacts_checked':local_checked,
            'protected_core_files_checked':len(provenance['protected_core_sha256']),
            'pdf_page_text_lengths':page_lengths,'word_margin_warnings':margin_warnings,'errors':errors}
    output=ROOT/'reports/.build/release-checks.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if errors: raise SystemExit(1)


if __name__=='__main__':main()
