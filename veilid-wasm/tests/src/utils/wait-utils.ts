import { veilidClient, VeilidRoutingContext, RecordKey } from 'veilid-wasm';

export const waitForMs = (milliseconds: number) => {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
};

export const asyncCallWithTimeout = async<T>(asyncPromise: Promise<T>, timeLimit: number) => {
  let timeoutHandle: ReturnType<typeof setTimeout>;

  const timeoutPromise = new Promise((_resolve, reject) => {
    timeoutHandle = setTimeout(
      () => reject(new Error('Async call timeout limit reached')),
      timeLimit
    );
  });

  return Promise.race([asyncPromise, timeoutPromise]).then(result => {
    clearTimeout(timeoutHandle);
    return result;
  })
}

export const waitForPublicAttachment = async () => {
  //console.log('waitForPublicAttachment...');

  const startTime = Date.now();
  while (true) {

    const state = await veilidClient.getState();
    if (state.attachment.publicInternetReady) {
      let attached = false
      switch (state.attachment.state) {
        case "Detached":
        case "Detaching":
        case "Attaching":
          break;
        default:
          attached = true;
          break;
      }
      if (attached) {
        break;
      }
    }
    await waitForMs(250);
    //console.log('waitForPublicAttachment loop...');
  }
  console.log(`waitForPublicAttachment took ${Date.now() - startTime}ms`);
}

export const waitForDetached = async () => {
  while (true) {
    const state = await veilidClient.getState();
    let detached = false
    switch (state.attachment.state) {
      case "Detached":
        detached = true;
        break;
      default:
        break;
    }
    if (detached) {
      break;
    }
    await waitForMs(1000);
  }
}

export const waitForShutdown = async () => {
  while (true) {
    const isShutdown = veilidClient.isShutdown();
    if (isShutdown) {
      break;
    }
    await waitForMs(1000);
  }
}

export const waitForOfflineSubkeyWrite = async (routingContext: VeilidRoutingContext, key: RecordKey) => {
  while ((await routingContext.inspectDHTRecord(key)).offlineSubkeys.length != 0) {
    await waitForMs(200);
  }
}

export const getLogTimestamp = () => {
  const now = new Date();

  // Get time components
  const hours = now.getHours();
  const minutes = now.getMinutes();
  const seconds = now.getSeconds();
  const milliseconds = now.getMilliseconds();

  // Pad with leading zeros where necessary to ensure two digits for hh, mm, ss
  const hh = hours.toString().padStart(2, '0');
  const mm = minutes.toString().padStart(2, '0');
  const ss = seconds.toString().padStart(2, '0');

  // Pad milliseconds with leading zeros to ensure three digits (000-999)
  const msec = milliseconds.toString().padStart(3, '0');

  return `${hh}:${mm}:${ss}.${msec}`;
}