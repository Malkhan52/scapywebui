$(document).ready(function(){
  $(".table-row").click(function(){
    var frame = $(this).find(".row-content").text();
    $("#selected_row").text(frame);
    console.log(frame);
  });
});
