export type Verdict = "scam" | "legitimate" | "verify";
export type Difficulty = "Starter" | "Intermediate" | "Expert";

export interface ScamScenario {
  id: string;
  category: string;
  difficulty: Difficulty;
  verdict: Verdict;
  title: string;
  message: string;
  context: string;
  explanation: string;
  nextStep: string;
  signal: string;
}

type Pattern = {
  title: string;
  message: string;
  context: string;
  verdict: Verdict;
  explanation: string;
  nextStep: string;
  signal: string;
};

type CategoryPack = {
  category: string;
  patterns: Pattern[];
  variations: string[];
};

const packs: CategoryPack[] = [
  {
    category: "Banking",
    variations: ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "your bank"],
    patterns: [
      {title:"Account-block threat",message:"Your {bank} account will be blocked in 30 minutes. Complete KYC at {bank}-secure.example immediately.",context:"You receive this message unexpectedly and it includes a link.",verdict:"scam",explanation:"A short deadline plus an unfamiliar login domain is a strong phishing pattern. A bank name inside a URL does not prove the domain belongs to the bank.",nextStep:"Do not open the link. Open your banking app yourself or use contact details from your bank card.",signal:"Urgency + unfamiliar domain"},
      {title:"Transaction notification",message:"Alert: ₹{amount} was debited from your account ending {digits}. If you do not recognise it, check your banking app.",context:"The message contains no link and does not ask you to reply with credentials.",verdict:"legitimate",explanation:"This is consistent with a routine debit alert: it reports an event and does not ask you to disclose secrets or make a payment. The wording alone cannot authenticate the sender.",nextStep:"Check the transaction in the bank app you open yourself if it is unfamiliar.",signal:"Informational alert"},
      {title:"KYC call-back request",message:"A caller claiming to be from {bank} asks you to read your OTP to keep your account active.",context:"The caller initiated contact and says the code is needed for verification.",verdict:"scam",explanation:"Never read an OTP to an unsolicited caller. The caller's claimed identity does not establish that they represent the bank.",nextStep:"End the call and contact the bank through a verified channel.",signal:"OTP disclosure request"},
      {title:"Routine service notice",message:"{bank}: planned mobile banking maintenance may affect services from 1:00–2:00 AM. No reply is required.",context:"There is no link, payment demand, or request for personal information.",verdict:"verify",explanation:"A maintenance notice can be genuine, but the sender label alone is not proof. Its content has no obvious scam request.",nextStep:"If the timing matters, check service notices inside the official app or website.",signal:"Plausible notice; sender unverified"},
      {title:"Refund processing fee",message:"Your bank refund is pending. Pay ₹{amount} processing charges to release it today.",context:"The message asks for a separate payment before a refund can be released.",verdict:"scam",explanation:"An unexpected fee to release money is a common advance-fee pattern. A message cannot prove that a refund exists.",nextStep:"Do not pay. Check the original transaction with the merchant or bank using official channels.",signal:"Pay-to-receive demand"}
    ]
  },
  {
    category: "UPI & Payments",
    variations: ["a buyer", "a seller", "a stranger", "a marketplace contact", "someone claiming to be support"],
    patterns: [
      {title:"QR code to receive money",message:"{actor} says they sent ₹{amount} and asks you to scan a QR code and enter your UPI PIN to receive it.",context:"You are supposed to be receiving money, not paying someone.",verdict:"scam",explanation:"Scanning a QR code and entering a UPI PIN can authorise a payment; a PIN is not generally needed to receive money.",nextStep:"Decline the request and verify incoming funds in your own UPI app.",signal:"PIN requested to receive money"},
      {title:"Payment received",message:"Your UPI app shows ₹{amount} received from a known contact. The amount appears in your own transaction history.",context:"You opened your payment app directly rather than relying on a screenshot.",verdict:"legitimate",explanation:"A matching entry in your own payment app is much stronger evidence than a message or screenshot. Still check the amount and sender before acting on it.",nextStep:"Confirm the transaction details in-app and keep the reference if needed.",signal:"Verified in your own app"},
      {title:"Collect request disguised as refund",message:"{actor} says a collect request must be approved to receive your ₹{amount} refund.",context:"The payment screen asks you to approve a request or enter a PIN.",verdict:"scam",explanation:"Approving a collect request may authorise money leaving your account. The claim that it is required for a refund is a warning sign.",nextStep:"Reject it and check refund status with the merchant through its official app.",signal:"Approval framed as refund"},
      {title:"Payment screenshot",message:"A buyer sends a screenshot showing a ₹{amount} transfer and asks you to hand over the item immediately.",context:"The money is not visible in your own payment app yet.",verdict:"verify",explanation:"Screenshots can be edited or show a failed or pending transaction. The screenshot alone cannot prove that funds arrived.",nextStep:"Wait until the payment appears in your own account before handing over goods.",signal:"Screenshot is not proof of payment"},
      {title:"Wrong-number refund",message:"A stranger says they accidentally sent you ₹{amount} and asks you to return it to a different UPI ID.",context:"You can see a payment entry, but the requested return destination differs from the sender.",verdict:"verify",explanation:"Mistakes can happen, but a separate return transfer can also be used in fraud or money-mule schemes. Do not rely on the stranger's explanation alone.",nextStep:"Contact your payment provider and use its official reversal process; do not send a separate transfer to a new ID.",signal:"Unverified refund route"}
    ]
  },
  {
    category: "OTP & Accounts",
    variations: ["your email", "your shopping account", "your social account", "your bank login", "your messaging account"],
    patterns: [
      {title:"Unrequested OTP",message:"Your {account} login code is {code}. Do not share it with anyone.",context:"You did not try to log in or request a code.",verdict:"verify",explanation:"A normal OTP notification is not automatically a scam, but an unexpected code can mean someone entered your details or made a mistake.",nextStep:"Do not share or use the code. Check account activity through the official app if this repeats.",signal:"Unexpected authentication attempt"},
      {title:"Agent asks for OTP",message:"A support agent says they need the {code}-digit OTP for {account} to cancel a suspicious login.",context:"You did not initiate the support conversation.",verdict:"scam",explanation:"A legitimate support agent should not ask you to disclose an authentication code. The story about cancelling a login is a common pretext.",nextStep:"End the conversation, secure the account through the official app, and report the contact.",signal:"Secret requested by unsolicited contact"},
      {title:"Password reset you requested",message:"You requested a password reset for {account}. If this was you, continue in the app; otherwise ignore this notice.",context:"You just requested the reset and the message directs you back to the app.",verdict:"legitimate",explanation:"This matches the expected flow for a reset you initiated and does not ask you to send a password or OTP to another person.",nextStep:"Complete the reset only in the official app or website you opened yourself.",signal:"Expected action; no secret disclosure"},
      {title:"Account recovery link",message:"Your {account} will be deleted today. Restore it at account-recovery.example or lose all data.",context:"The message is unexpected and pressures you to use its link.",verdict:"scam",explanation:"A threat of immediate deletion combined with an unfamiliar domain is a strong phishing indicator.",nextStep:"Avoid the link and check account status from the official app or a known address.",signal:"Threat + unfamiliar recovery link"},
      {title:"Security alert",message:"New sign-in detected for {account}. If this wasn't you, review recent activity in the app.",context:"The message contains no shortened link and asks you to navigate to the app yourself.",verdict:"verify",explanation:"Security alerts can be genuine, but sender names can be spoofed. The content itself is plausible and does not demand secrets.",nextStep:"Open the app independently, review sessions, and change your password if needed.",signal:"Plausible alert; authenticate independently"}
    ]
  },
  {
    category: "Courier & Delivery",
    variations: ["a parcel", "a prepaid order", "a return pickup", "an international package", "a delivery"],
    patterns: [
      {title:"Tiny redelivery fee",message:"Your {parcel} is on hold. Pay ₹{amount} within 15 minutes at parcel-fee.example to reschedule.",context:"You were not expecting a fee and the link is unfamiliar.",verdict:"scam",explanation:"Small fees can be used to harvest card details. The short deadline and unfamiliar domain add risk.",nextStep:"Check the order in the courier's official app or website, opened independently.",signal:"Unexpected fee + deadline"},
      {title:"Expected delivery update",message:"Your {parcel} is out for delivery today. Check tracking in the courier app you already use.",context:"You are expecting an order and the message does not include a payment link.",verdict:"legitimate",explanation:"This is consistent with a routine delivery update. The message itself does not request sensitive information or money.",nextStep:"Use your existing courier app to check tracking if needed.",signal:"Expected informational update"},
      {title:"Address correction link",message:"Delivery failed because your address is incomplete. Enter your full address and card details at delivery-fix.example.",context:"You did not receive a delivery attempt and the page asks for card information.",verdict:"scam",explanation:"A delivery address correction should not require card details. The unexpected link and excessive data request are suspicious.",nextStep:"Do not submit details. Check the tracking number through the official courier channel.",signal:"Excessive personal/financial data request"},
      {title:"Cash-on-delivery confirmation",message:"Your {parcel} is marked cash on delivery for ₹{amount}. Confirm the order in the shopping app.",context:"You remember placing an order but are unsure about this parcel.",verdict:"verify",explanation:"COD updates can be legitimate, but unexpected parcels can also be used to confuse recipients. The message alone cannot establish the order's origin.",nextStep:"Check your order history before accepting or paying.",signal:"Order context needs checking"},
      {title:"Fake customs release",message:"International parcel detained. Transfer ₹{amount} customs clearance to this personal UPI ID today.",context:"The sender gives no verifiable tracking or official payment route.",verdict:"scam",explanation:"A personal UPI transfer demanded to release a parcel is a serious warning sign. Customs and courier claims should be independently verified.",nextStep:"Do not transfer funds. Verify the shipment and any duty through official courier or customs channels.",signal:"Unverified personal payment demand"}
    ]
  },
  {
    category: "Jobs & Gigs",
    variations: ["a remote data-entry role", "a product-rating task", "a part-time assistant role", "a work-from-home position", "a freelance project"],
    patterns: [
      {title:"Pay to unlock work",message:"Earn ₹{amount} daily with {job}. Pay a refundable registration fee to activate your worker account.",context:"The recruiter promises high earnings but requires money before work starts.",verdict:"scam",explanation:"Upfront fees paired with unusually high guaranteed earnings are common job-scam patterns.",nextStep:"Do not pay. Verify the company through independently found contact details and written terms.",signal:"Upfront fee + unrealistic income"},
      {title:"Interview invitation",message:"Your application for {job} has been shortlisted. Choose an interview slot on the employer's official careers portal.",context:"You applied to the company and can navigate to its known careers site yourself.",verdict:"legitimate",explanation:"An interview invitation is consistent with a normal hiring process, especially when it matches an application you made. The claim should still be verified.",nextStep:"Check the application status through the employer's independently located careers page.",signal:"Matches an application you made"},
      {title:"Paid training demand",message:"You are selected for {job}. Send ₹{amount} for mandatory training materials before receiving your offer letter.",context:"There was no interview and the recruiter uses a personal messaging account.",verdict:"scam",explanation:"Paying a recruiter before a verifiable offer, particularly through a personal account, is a significant warning sign.",nextStep:"Do not pay or send identity documents. Contact the company using official details.",signal:"Payment before verified employment"},
      {title:"Freelance contract",message:"A client shares a written scope, milestones, and payment terms for {job}; no fee is required to start.",context:"The client identity and project history still need checking.",verdict:"verify",explanation:"Clear scope and no upfront fee are positive signs, but a polished contract alone does not prove the client is genuine.",nextStep:"Verify the client, use a reputable platform or contract, and agree on protected milestone payments.",signal:"Plausible offer; client unverified"},
      {title:"Task balance trap",message:"Your task account shows ₹{amount} profit, but you must deposit more money to unlock withdrawal.",context:"The platform displays earnings but requires a new deposit before payout.",verdict:"scam",explanation:"Fake task platforms often display fabricated balances and demand deposits to unlock withdrawals.",nextStep:"Do not deposit more. Preserve evidence and contact your payment provider if you already paid.",signal:"Pay more to withdraw"}
    ]
  },
  {
    category: "Investments",
    variations: ["a crypto scheme", "a stock tips group", "a trading bot", "a private investment club", "a high-yield savings plan"],
    patterns: [
      {title:"Guaranteed weekly returns",message:"Invest ₹{amount} in {investment}. Earn 30% every week with zero risk; slots close tonight.",context:"The promoter pressures you to transfer money quickly.",verdict:"scam",explanation:"Guaranteed unusually high returns and urgency are classic investment fraud warning signs. All investments carry risk.",nextStep:"Do not transfer funds based on the message. Verify the entity and adviser through official regulatory sources.",signal:"Guaranteed returns + pressure"},
      {title:"Regulated fund statement",message:"Your investment platform statement is available. Open the official app to review holdings and fees.",context:"You already have an account with this platform and no link is supplied.",verdict:"legitimate",explanation:"This is consistent with an informational account notice, though the sender still cannot be authenticated from text alone.",nextStep:"Open the app directly and review the statement there.",signal:"Informational account notice"},
      {title:"Secret insider tip",message:"An insider guarantees a multibagger tomorrow. Send ₹{amount} to a personal account to join the VIP group.",context:"The sender provides no verifiable registration or risk disclosure.",verdict:"scam",explanation:"Guaranteed gains, secret insider claims, and personal-account transfers are major warning signs.",nextStep:"Do not pay. Verify the adviser and platform independently before considering any investment.",signal:"Guaranteed gain + personal transfer"},
      {title:"Unsolicited portfolio review",message:"A stranger says they can recover your investment losses if you share your trading login and OTP.",context:"The contact found you through a social media post.",verdict:"scam",explanation:"No legitimate adviser needs your account password or OTP to review a portfolio. Recovery scams often target people who have already lost money.",nextStep:"Do not share credentials. Contact your broker through its official support channel.",signal:"Credential request disguised as help"},
      {title:"Investment webinar",message:"A firm invites you to a free webinar explaining market risks and says returns are not guaranteed.",context:"The firm and presenter have not yet been independently verified.",verdict:"verify",explanation:"Risk disclosures and a free webinar are not proof of legitimacy or fraud. Verify the firm, speaker, and any later product claims.",nextStep:"Research the organiser independently and never invest based solely on a webinar or social proof.",signal:"More context needed"}
    ]
  },
  {
    category: "Impersonation",
    variations: ["a police officer", "a courier agent", "a bank investigator", "a government official", "a customer-support agent"],
    patterns: [
      {title:"Digital arrest threat",message:"{official} says your identity is linked to a crime. Stay on video call and transfer ₹{amount} to clear your name.",context:"The caller forbids you from speaking to family or ending the call.",verdict:"scam",explanation:"Threats, isolation, video-call pressure, and payment demands are hallmarks of impersonation fraud. Law enforcement does not resolve a case by demanding transfers to personal accounts.",nextStep:"End the call, tell someone you trust, and contact the relevant authority through a verified number.",signal:"Intimidation + isolation + money demand"},
      {title:"Routine service callback",message:"You requested a callback from {official}; the agent asks you to confirm the issue but not your password or OTP.",context:"You initiated the request through the official website.",verdict:"verify",explanation:"A callback you requested is plausible, but the caller's identity still needs confirmation. Legitimate context reduces suspicion without proving identity.",nextStep:"Use the case number and official contact route; never disclose passwords or OTPs.",signal:"Expected contact; verify identity"},
      {title:"Family emergency transfer",message:"A person claiming to be your cousin says they are stranded and need ₹{amount} immediately. They ask you not to call.",context:"The message arrives from a new number and discourages verification.",verdict:"scam",explanation:"An urgent money request plus secrecy and refusal to verify is a strong impersonation pattern.",nextStep:"Call your relative on a known number or verify through another trusted person before sending money.",signal:"Urgency + secrecy"},
      {title:"Appointment reminder",message:"Reminder: your appointment is tomorrow at 11 AM. Call the number on your original booking confirmation if you need to reschedule.",context:"You remember booking the appointment and the message does not ask for payment.",verdict:"legitimate",explanation:"This resembles a routine reminder tied to an expected appointment. The text alone cannot authenticate the sender, but there is no obvious scam request.",nextStep:"Check your original booking confirmation if the details are unfamiliar.",signal:"Expected informational reminder"},
      {title:"Video-call intimidation",message:"An official-looking caller demands that you install a screen-sharing app and keep your camera on during an investigation.",context:"The caller threatens arrest if you disconnect.",verdict:"scam",explanation:"Threats combined with remote-access or screen-sharing demands can expose your accounts and financial activity.",nextStep:"Do not install the app or share your screen. Disconnect and independently contact the relevant organisation.",signal:"Remote access under coercion"}
    ]
  },
  {
    category: "Shopping & Refunds",
    variations: ["a phone order", "a clothing order", "a grocery order", "an electronics order", "a cancelled purchase"],
    patterns: [
      {title:"Refund needs UPI PIN",message:"Your {order} refund of ₹{amount} is ready. Enter your UPI PIN on this page to receive it.",context:"The message links to an unfamiliar page and requests a PIN.",verdict:"scam",explanation:"A UPI PIN authorises payments; it is not a requirement for receiving a refund. The unfamiliar page adds risk.",nextStep:"Do not enter the PIN. Open the retailer's official app and check refund status.",signal:"PIN requested for refund"},
      {title:"Refund status in app",message:"Your refund for {order} has been initiated. The status and expected timeline are available in your order history.",context:"You cancelled the order and can see the same status in the official app.",verdict:"legitimate",explanation:"The notification matches an action you took and is corroborated in your account. That is stronger evidence than message wording alone.",nextStep:"Track the refund in the official app and contact support there if it is delayed.",signal:"Corroborated in account"},
      {title:"Too-good-to-be-true deal",message:"A social account offers a new flagship phone for 90% off if you pay by direct bank transfer in the next 10 minutes.",context:"The seller has no verifiable store history and refuses protected payment methods.",verdict:"scam",explanation:"Extreme discounts, urgency, and refusal of safer payment methods are common shopping-fraud signs.",nextStep:"Do not transfer money. Verify the seller and buy through a trusted marketplace with buyer protection.",signal:"Extreme discount + unsafe payment"},
      {title:"Order cancellation OTP",message:"A caller says they can cancel {order} but asks you to read out the OTP sent to your phone.",context:"You did request a cancellation, but the caller contacted you unexpectedly.",verdict:"scam",explanation:"Even when the underlying order is real, an unsolicited person asking for an OTP is not a safe cancellation process.",nextStep:"Do not share the code. Cancel through the retailer app or its verified support channel.",signal:"OTP request during cancellation"},
      {title:"Return pickup update",message:"Your return pickup is scheduled for tomorrow. Check the return details in the shopping app.",context:"You recently requested a return and the status matches your account.",verdict:"legitimate",explanation:"This is consistent with a routine return update that is corroborated by your own order history.",nextStep:"Confirm the pickup in the app and do not pay unexpected fees to an unsolicited contact.",signal:"Expected and corroborated"}
    ]
  },
  {
    category: "Utilities & Government",
    variations: ["electricity", "LPG", "a municipal service", "a tax filing", "a benefits application"],
    patterns: [
      {title:"Power disconnection threat",message:"Your {service} connection will be cut tonight. Pay ₹{amount} through this personal UPI ID immediately.",context:"The sender gives no verifiable bill reference and demands a personal transfer.",verdict:"scam",explanation:"Threatening immediate disconnection and demanding payment to a personal UPI ID are strong warning signs.",nextStep:"Check your bill in the provider's official app or call the number on a previous bill.",signal:"Threat + personal payment destination"},
      {title:"Bill generated",message:"Your monthly {service} bill is available in the provider's official app. Check the due date and amount there.",context:"No payment link is supplied and you can access your account independently.",verdict:"legitimate",explanation:"This is a normal informational reminder. Use the official app you already know rather than trusting a link in an unexpected message.",nextStep:"Review the bill in your account and pay through an official payment route.",signal:"Informational reminder"},
      {title:"Benefit release fee",message:"Your {service} benefit of ₹{amount} is approved. Pay a processing fee first to release the funds.",context:"The message asks for a fee and provides no official case reference.",verdict:"scam",explanation:"A fee demanded by an unsolicited message to release a benefit is an advance-fee warning sign.",nextStep:"Do not pay. Check application status through the relevant official government portal.",signal:"Fee to release funds"},
      {title:"Tax document notice",message:"A tax document is available in your account. Sign in by typing the official portal address yourself.",context:"The message does not demand immediate payment or ask you to disclose credentials to a caller.",verdict:"verify",explanation:"A tax-related notice can be genuine, but message text alone cannot authenticate it. The safest approach is to navigate independently.",nextStep:"Open the official portal yourself and check notices in your account.",signal:"Plausible notice; verify independently"},
      {title:"Remote-access utility support",message:"A utility agent says they can fix your bill by installing a remote-control app and sharing your screen.",context:"You did not request technical support and the agent is pressuring you to act.",verdict:"scam",explanation:"Unsolicited remote-access requests can expose banking apps, messages, and personal information.",nextStep:"Decline access and contact the utility provider through a verified channel.",signal:"Unsolicited remote access"}
    ]
  },
  {
    category: "Social Media & Links",
    variations: ["Instagram", "WhatsApp", "Facebook", "a gaming account", "an email account"],
    patterns: [
      {title:"Copyright threat link",message:"Your {platform} account will be permanently deleted today. Appeal at creator-protection.example and enter your password.",context:"The link is unfamiliar and the message creates a short deadline.",verdict:"scam",explanation:"An urgent threat combined with a credential form on an unfamiliar domain is a phishing pattern.",nextStep:"Do not use the link. Check account notifications from inside the official app.",signal:"Urgent threat + password form"},
      {title:"Friend sends a strange link",message:"A friend sends a shortened link with the message 'Is this you in this video?' and no other context.",context:"The message is unusual for the person and the destination is hidden.",verdict:"verify",explanation:"The account may be compromised, or the friend may genuinely be sharing something. A shortened link hides the destination.",nextStep:"Ask the friend through another channel before opening it; report the account if it appears compromised.",signal:"Unexpected link; sender context unclear"},
      {title:"Login alert you recognise",message:"A sign-in alert appears inside {platform} immediately after you log in on your new phone.",context:"You initiated the sign-in and can see the same device in account settings.",verdict:"legitimate",explanation:"The alert matches an action you just took and is corroborated in account settings.",nextStep:"Confirm the device details and keep two-factor authentication enabled.",signal:"Expected and corroborated event"},
      {title:"Verification badge fee",message:"A social-media agent promises a verified badge if you pay ₹{amount} and send your login code.",context:"The agent contacted you through direct messages and is not listed in official support.",verdict:"scam",explanation:"Paying an unsolicited agent and sharing a login code can lead to account takeover. Verification should be handled through official platform processes.",nextStep:"Do not pay or share codes. Use the platform's own settings and report the account.",signal:"Credential request + unofficial fee"},
      {title:"Password manager warning",message:"Your password manager reports that a saved password appeared in a known data breach and recommends changing it in the app.",context:"The alert appears inside the password manager you opened yourself.",verdict:"legitimate",explanation:"A breach warning inside a trusted app can be a useful security notice. It does not mean the app should ask you to reveal the existing password to a person.",nextStep:"Change the affected password through the real service and use a unique password.",signal:"In-app security warning"}
    ]
  }
];

const amounts = ["499", "999", "1,499", "2,500", "4,999"];
const digits = ["4821", "1906", "7734", "2618", "9052"];
const codes = ["6-digit", "one-time", "login", "verification", "security"];
const bankNames = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "your bank"];
const accounts = ["email", "shopping account", "social account", "bank login", "messaging account"];
const parcels = ["parcel", "prepaid order", "return pickup", "international package", "delivery"];
const jobs = ["remote data-entry role", "product-rating task", "part-time assistant role", "work-from-home position", "freelance project"];
const investments = ["crypto scheme", "stock tips group", "trading bot", "private investment club", "high-yield savings plan"];
const officials = ["police officer", "courier agent", "bank investigator", "government official", "customer-support agent"];
const orders = ["phone order", "clothing order", "grocery order", "electronics order", "cancelled purchase"];
const services = ["electricity", "LPG", "municipal service", "tax filing", "benefits application"];
const platforms = ["Instagram", "WhatsApp", "Facebook", "gaming account", "email account"];
const actors = ["a buyer", "a seller", "a stranger", "a marketplace contact", "someone claiming to be support"];
const jobNames = ["data entry", "product rating", "part-time assistant work", "remote admin work", "freelance tasks"];
const investmentNames = ["a crypto scheme", "a stock tips group", "a trading bot", "a private investment club", "a high-yield savings plan"];
const officialNames = ["a police officer", "a courier agent", "a bank investigator", "a government official", "a customer-support agent"];
const serviceNames = ["electricity", "LPG", "municipal service", "tax filing", "benefits application"];
const accountNames = ["email", "shopping account", "social account", "bank login", "messaging account"];
const orderNames = ["phone order", "clothing order", "grocery order", "electronics order", "cancelled purchase"];
const platformNames = ["Instagram", "WhatsApp", "Facebook", "gaming account", "email account"];
const parcelNames = ["parcel", "prepaid order", "return pickup", "international package", "delivery"];
const jobVariations = ["a remote data-entry role", "a product-rating task", "a part-time assistant role", "a work-from-home position", "a freelance project"];
const investVariations = ["a crypto scheme", "a stock tips group", "a trading bot", "a private investment club", "a high-yield savings plan"];
const officialVariations = ["a police officer", "a courier agent", "a bank investigator", "a government official", "a customer-support agent"];
const utilityVariations = ["electricity", "LPG", "a municipal service", "a tax filing", "a benefits application"];
const shoppingVariations = ["a phone order", "a clothing order", "a grocery order", "an electronics order", "a cancelled purchase"];
const socialVariations = ["Instagram", "WhatsApp", "Facebook", "a gaming account", "an email account"];
const upiActors = ["a buyer", "a seller", "a stranger", "a marketplace contact", "someone claiming to be support"];

const replacements: Record<string, string[]> = {
  "{bank}": bankNames,
  "{amount}": amounts,
  "{digits}": digits,
  "{code}": codes,
  "{account}": accountNames,
  "{parcel}": parcelNames,
  "{job}": jobVariations,
  "{investment}": investVariations,
  "{official}": officialVariations,
  "{order}": shoppingVariations,
  "{service}": utilityVariations,
  "{platform}": socialVariations,
  "{actor}": upiActors
};

function render(template: string, variant: number, seed: number) {
  return template.replace(/\{[^}]+\}/g, token => {
    const values = replacements[token];
    return values ? values[(variant + seed) % values.length] : token;
  });
}

export const scamSchoolScenarios: ScamScenario[] = packs.flatMap((pack, packIndex) =>
  pack.patterns.flatMap((pattern, patternIndex) =>
    pack.variations.map((variation, variantIndex) => {
      const idNumber = packIndex * 25 + patternIndex * 5 + variantIndex + 1;
      const seed = variantIndex;
      const bank = pack.category === "Banking" ? variation : undefined;
      const actor = pack.category === "UPI & Payments" ? variation : undefined;
      const account = pack.category === "OTP & Accounts" ? variation : undefined;
      const parcel = pack.category === "Courier & Delivery" ? variation : undefined;
      const job = pack.category === "Jobs & Gigs" ? variation : undefined;
      const investment = pack.category === "Investments" ? variation : undefined;
      const official = pack.category === "Impersonation" ? variation : undefined;
      const order = pack.category === "Shopping & Refunds" ? variation : undefined;
      const service = pack.category === "Utilities & Government" ? variation : undefined;
      const platform = pack.category === "Social Media & Links" ? variation : undefined;
      const replacementsForPattern: Record<string, string> = {
        "{bank}": bank ?? bankNames[variantIndex],
        "{actor}": actor ?? upiActors[variantIndex],
        "{account}": account ?? accountNames[variantIndex],
        "{parcel}": parcel ?? parcelNames[variantIndex],
        "{job}": job ?? jobVariations[variantIndex],
        "{investment}": investment ?? investVariations[variantIndex],
        "{official}": official ?? officialVariations[variantIndex],
        "{order}": order ?? shoppingVariations[variantIndex],
        "{service}": service ?? utilityVariations[variantIndex],
        "{platform}": platform ?? socialVariations[variantIndex],
        "{amount}": amounts[(variantIndex + patternIndex) % amounts.length],
        "{digits}": digits[variantIndex],
        "{code}": codes[variantIndex]
      };
      const fill = (s: string) => s.replace(/\{[^}]+\}/g, token => replacementsForPattern[token] ?? token);
      const difficulty: Difficulty = patternIndex < 2 ? "Starter" : patternIndex < 4 ? "Intermediate" : "Expert";
      return {
        id: `SS-${String(idNumber).padStart(3, "0")}`,
        category: pack.category,
        difficulty,
        verdict: pattern.verdict,
        title: pattern.title,
        message: fill(pattern.message),
        context: fill(pattern.context),
        explanation: pattern.explanation,
        nextStep: pattern.nextStep,
        signal: pattern.signal
      };
    })
  )
);

export const scenarioCategories = ["All", ...packs.map(pack => pack.category)];
