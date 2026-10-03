// Generates a fake scam SMS screenshot for testing /api/analyze/image
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.setViewport({ width: 390, height: 500 });
  await page.setContent(`
    <div style="font-family:Arial; padding:16px; background:#fff; height:480px;">
      <div style="background:#e8f5e9; border-radius:12px; padding:14px; max-width:85%;">
        <div style="font-size:11px; color:#888; margin-bottom:6px;">SBI Alerts • 9:41 AM</div>
        <div style="font-size:15px; color:#111; line-height:1.5;">
          Dear Customer, your SBI account will be BLOCKED today.
          Update your KYC immediately at https://sbi-kyc-update.xyz/verify
          or your account will be closed permanently.
        </div>
      </div>
    </div>`);
  await page.screenshot({ path: 'test_screenshot.png' });
  await browser.close();
  console.log('screenshot saved');
})();
