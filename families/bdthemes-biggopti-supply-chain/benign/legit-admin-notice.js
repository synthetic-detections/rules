// generic WP admin notice fetcher (benign)
jQuery(function($){
  fetch(ajaxurl + '?action=get_notices')
    .then(r=>r.text())
    .then(html=>$('#notice-wrap').html(html));
});
