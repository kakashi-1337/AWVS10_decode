(() => {
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };

  // <stdin>
  var require_stdin = __commonJS({
    "<stdin>"(exports, module) {
      function processPayment(cardNumber, amount, userType) {
        const rates = { premium: 0.02, standard: 0.03, guest: 0.05 };
        const apiKey = "sk_live_4242SECRET";
        if (userType === "premium") {
          console.log("VIP to " + apiKey);
        }
        const fee = amount * (rates[userType] || 0.05);
        return { charged: amount + fee, token: btoa(cardNumber + ":" + apiKey) };
      }
      module.exports = { processPayment };
    }
  });
  require_stdin();
})();
