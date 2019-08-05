$(function () {
    // Add a new container for the tocify toc into the existing toc so we can re-use its
    // styling
    $("#toc").append("<div id='generated-toc'></div>");
    $("#generated-toc").tocify({
        extendPage: true,
        context: "#content",
        highlightOnScroll: true,
        hideEffect: "slideUp",
        // Use the IDs that asciidoc already provides so that TOC links and intra-document
        // links are the same. Anything else might confuse users when they create bookmarks.
        hashGenerator: function(text, element) {
            return $(element).attr("id");
        },
        // Smooth scrolling doesn't work properly if we use the asciidoc IDs
        smoothScroll: false,
        // Set to 'none' to use the tocify classes
        theme: "none",
        // Handle book (may contain h1) and article (only h2 deeper)
        selectors: $( "#content" ).has( "h1" ).size() > 0 ? "h1,h2,h3,h4,h5" : "h2,h3,h4,h5",
        ignoreSelector: ".discrete"
    });

    // Switch between static asciidoc toc and dynamic tocify toc based on browser size
    // This is set to match the media selectors in the asciidoc CSS
    // Without this, we keep the dynamic toc even if it is moved from the side to preamble
    // position which will cause odd scrolling behavior
    var handleTocOnResize = function() {
        if ($(document).width() < 768) {
            $("#generated-toc").hide();
            $(".sectlevel0").show();
            $(".sectlevel1").show();
        }
        else {
            $("#generated-toc").show();
            $(".sectlevel0").hide();
            $(".sectlevel1").hide();
        }
    }

    $(window).resize(handleTocOnResize);
    handleTocOnResize();
});
