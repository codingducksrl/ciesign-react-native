import { PDFArray, PDFDict, PDFDocument, PDFHexString, PDFName, PDFNumber, PDFString } from '@cantoo/pdf-lib';

import { type Bytes, type Signer, concat, hex, sha256, signedData } from './cms';

export type PadesOptions = { reason?: string; location?: string; contactInfo?: string };

const CONTENTS_SIZE = 8192;
const BYTE_RANGE = '/ByteRange [ 0 /********** /********** /********** ]';

const indexOf = (bytes: Bytes, text: string, from: number) => {
  search: for (let i = from; i <= bytes.length - text.length; i++) {
    for (let j = 0; j < text.length; j++) if (bytes[i + j] !== text.charCodeAt(j)) continue search;
    return i;
  }
  throw new Error(`${text} not found`);
};

/** Adds an invisible PAdES baseline B-B signature (ETSI.CAdES.detached) as an incremental update. */
export async function signPades(pdf: Bytes, signer: Signer, options: PadesOptions = {}): Promise<Bytes> {
  const doc = await PDFDocument.load(pdf, { forIncrementalUpdate: true, updateMetadata: false });
  const { context, catalog } = doc;
  const docMdp = catalog.lookupMaybe(PDFName.of('Perms'), PDFDict)?.lookupMaybe(PDFName.of('DocMDP'), PDFDict);
  const params = docMdp?.lookupMaybe(PDFName.of('Reference'), PDFArray)?.lookupMaybe(0, PDFDict)?.lookupMaybe(PDFName.of('TransformParams'), PDFDict);
  if (params?.lookupMaybe(PDFName.of('P'), PDFNumber)?.asNumber() === 1) throw new Error('The PDF is certified against any change');
  const page = doc.getPage(0);
  const form = catalog.getOrCreateAcroForm();
  const names = new Set(form.getAllFields().map(([field]) => field.getFullyQualifiedName()));
  let n = 1;
  while (names.has(`Signature${n}`)) n++;

  const text = (value?: string) => (value ? PDFHexString.fromText(value) : undefined);
  const signature = context.register(
    context.obj({
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'ETSI.CAdES.detached',
      ByteRange: [0, PDFName.of('**********'), PDFName.of('**********'), PDFName.of('**********')],
      Contents: PDFHexString.of('0'.repeat(CONTENTS_SIZE * 2)),
      M: PDFString.fromDate(new Date()),
      Reason: text(options.reason),
      Location: text(options.location),
      ContactInfo: text(options.contactInfo),
    }),
  );
  const widget = context.register(
    context.obj({
      Type: 'Annot',
      Subtype: 'Widget',
      FT: 'Sig',
      T: PDFHexString.fromText(`Signature${n}`),
      V: signature,
      F: 132, // Print | Locked
      Rect: [0, 0, 0, 0],
      P: page.ref,
    }),
  );
  // Not page.node.addAnnot(): it normalizes the page, rewriting its content streams.
  const annots = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
  if (annots) annots.push(widget);
  else page.node.set(PDFName.of('Annots'), context.obj([widget]));
  form.addField(widget);
  form.dict.set(PDFName.of('SigFlags'), PDFNumber.of(3)); // SignaturesExist | AppendOnly

  // Object streams would compress the signature dictionary, which must stay in plain bytes.
  const out = concat(pdf, await doc.saveIncremental(context.snapshot!, { useObjectStreams: false }));

  const byteRangeAt = indexOf(out, BYTE_RANGE, pdf.length);
  const start = indexOf(out, '<', indexOf(out, '/Contents', byteRangeAt));
  const end = start + CONTENTS_SIZE * 2 + 2;
  const byteRange = `/ByteRange [0 ${start} ${end} ${out.length - end}]`.padEnd(BYTE_RANGE.length);
  out.set(Uint8Array.from(byteRange, (c) => c.charCodeAt(0)), byteRangeAt);

  const cms = await signedData(await sha256(concat(out.subarray(0, start), out.subarray(end))), signer);
  if (cms.length > CONTENTS_SIZE) throw new Error('Signature larger than the reserved space');
  out.set(Uint8Array.from(hex(cms), (c) => c.charCodeAt(0)), start + 1);
  return out;
}
