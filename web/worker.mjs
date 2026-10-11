// Runs the engine off the main thread so large pickles or multi-GB hashing never freeze the page.
import {inspectAll} from './engine.mjs';

self.onmessage = async ({data}) => {
  try {
    const report = await inspectAll(data.entries, {
      hash: data.hash, target: data.target,
      onProgress: (done, total, path) => self.postMessage({type: 'progress', done, total, path}),
    });
    self.postMessage({type: 'done', report});
  } catch (e) {
    self.postMessage({type: 'error', message: e && e.message ? e.message : String(e)});
  }
};
