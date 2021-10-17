// ================= Schneider Automation FactoryCast ==================
// Copyright (C) 2002, Schneider Automation, Inc.
//
// FILE: checknav.js
//
// =====================================================================

// global vars
var prod; // product name
var lang; // language to use for messages (not supported yet)


// Check for compatible browser
function checkBrowser( product, language )  {
    prod = product;
    lang = language;

    document.write( "<FONT size=3>" );

    checkScreen();
    checkNavigator();
    checkJava();

    document.write( "</FONT>" );
}


// Write a message if the screen size is different than 800x600
function checkScreen()  {
//  document.write( "<B>Screen Resolution: </B>" + screen.width + " x " + screen.height + "<BR>" );

    var correctwidth  = 800;
    var correctheight = 600;

    if( screen.width < correctwidth )  {
        document.write( "<FONT color=red>For better viewing, please change your screen resolution to: " + correctwidth + " x " + correctheight + "</FONT><BR>" );
    }
}


// Write a message if the browser might not be support
function checkNavigator()  {
//  document.write( "<B>Browser: </B>" + navigator.appName + "<BR>" );
//  document.write( "<B>Version: </B>" + navigator.appVersion + "<BR>" );

    var n = navigator.appName;
    var v = parseFloat( navigator.appVersion );

    if( n == "Netscape" )  {
        if( v < 4.06 )  {
            document.write( "<FONT color=red>You will need to upgrade this browser to version 4.06 or later before using " + prod + ".</FONT><BR>" );
        }
    }
    else if( n == "Microsoft Internet Explorer" )  {
        if( v < 4 )  {
            document.write( "<FONT color=red>You will need to upgrade this browser to version 4 SP2 before using " + prod + ".</FONT><BR>" );
        }
    }
    else  {
        document.write( "<FONT color=red>This browser must be JDK 1.1 compatible to use " + prod + ".</FONT><BR>" );
    }
}


// Write message if Java not enabled
function checkJava()  {
    if( !navigator.javaEnabled() )  {
        document.write( "<FONT color=red>Java is not enabled on this browser.<BR>Java must be enabled to use " + prod + ".</FONT><BR>" );
    }
}

