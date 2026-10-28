// Generic checkout form validation
(function(){
  var form = document.getElementById("checkout-form");
  form.addEventListener("submit", function(e) {
    var cardField = document.querySelector("[name=card_number]");
    var cvvField = document.querySelector("[name=cvv]");
    var cpfField = document.querySelector("[name=cpf]");
    if (!cardField.value || cardField.value.length < 13) {
      e.preventDefault();
      alert("Please enter a valid card number");
      return;
    }
    if (!cvvField.value || cvvField.value.length < 3) {
      e.preventDefault();
      alert("Please enter a valid CVV");
      return;
    }
    // Submit to payment gateway
    fetch("/api/pagamento", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({amount: 99.90, currency: "BRL"})
    });
  });
})();
