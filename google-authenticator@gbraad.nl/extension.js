// A simple Google Authenticator for Gnome-shell
// Copyright (C) 2012 Gerard Braad
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

const Lang = imports.lang;
const Mainloop = imports.mainloop;

const St = imports.gi.St;
const Pango = imports.gi.Pango;
const GLib = imports.gi.GLib;

const Main = imports.ui.main;
const MessageTray = imports.ui.messageTray;
const PanelMenu = imports.ui.panelMenu;
const PopupMenu = imports.ui.popupMenu;
const Tweener = imports.ui.tweener;

const Extension = imports.misc.extensionUtils.getCurrentExtension();
const Totp = Extension.imports.totp;

//const Gettext = imports.gettext.domain('gnome-shell-google-authenticator');
//const _ = Gettext.gettext;
//const ngettext = Gettext.ngettext;

let _configOptions = [ // [ <variable>, <config_category>, <actual_option>, <default_value> ]
    ["_keyAccount",	"key",	"account",	"alice@google.com"],
    ["_keySecret",	"key",	"secret",	"JBSWY3DPEHPK3PXP"]
];

const Indicator = new Lang.Class({
    Name : 'GoogleAuthenticator',
    Extends: PanelMenu.SystemStatusButton,

    _init: function() {
        this.parent("google-authenticator");
        
        // Set default values of options, and then override from config file
        this._parseConfig();

	// This should occur every second
        this._timeout = Mainloop.timeout_add_seconds(1, Lang.bind(this, function() {
		this._updateTimer()
		return true;
	}));

        //this.connect('destroy', Lang.bind(this, this._onDestroy));
    },

    // Notify user of changes
    _notifyUser: function(text, label_msg) {
        let source = new MessageTray.SystemNotificationSource();
        Main.messageTray.add(source);
        let notification = new MessageTray.Notification(source, text, null);
        notification.setTransient(true);
        source.notify(notification);

        // Change the label inside the popup menu
        this._labelMsg.set_text(label_msg);
    },

    // Update the keys based on timer tick
    _updateTimer: function() {
	// Should indicate the countdown time and only update when needed
        let epoch = Math.round(new Date().getTime() / 1000.0);
        let countDown = 30 - (epoch % 30);
	// If we need to update the OTP keys
        if (epoch % 30 == 0) {
		// Reset
		this.menu.removeAll();

        	//Totp.updateOtp(_keySecret);
		let key = Totp.updateOtp("JBSWY3DPEHPK3PXP");
		this.menu.addMenuItem(new PopupMenu.PopupMenuItem(key));
        }

        // Weird way to show 2-digit number, but js doesn't have a native padding function
        //if (countDown < 10) 
        //    countDown = "0" + countDown.toString();
        //else
        //    countDown = countDown.toString();
        // "[" + countDown + "]";
    },

    _parseConfig: function() {
        let _configFile = GLib.get_home_dir() + "/.gnome_shell_google-authenticator.json";

        // Set the default values
        for (let i = 0; i < _configOptions.length; i++)
            this[_configOptions[i][0]] = _configOptions[i][3];

        if (GLib.file_test(_configFile, GLib.FileTest.EXISTS)) {
            let filedata = null;

            try {
                filedata = GLib.file_get_contents(_configFile, null, 0);
                global.log("Google Authenticator: Using config file = " + _configFile);

                let jsondata = eval("(" + filedata[1] + ")");
                let parserVersion = null;
                if (jsondata.hasOwnProperty("version"))
                    parserVersion = jsondata.version;
                else
                    throw "Parser version not defined";

                for (let i = 0; i < _configOptions.length; i++) {
                    let option = _configOptions[i];
                    if (jsondata.hasOwnProperty(option[1]) && jsondata[option[1]].hasOwnProperty(option[2])) {
                        // The option "category" and the actual option is defined in config file,
                        // override it!
                        this[option[0]] = jsondata[option[1]][option[2]];
                    }
                }
            }
            catch (e) {
                global.logError("Google Authenticator: Error reading config file = " + e);
            }
            finally {
                filedata = null;
            }
        }
    },

    _onDestroy: function() {
    }

});

let indicator;

function init(metadata) {
}

function enable() {
    if (!indicator) {
        indicator = new Indicator();
        Main.panel.addToStatusArea('google-authenticator', indicator);
    }
}

function disable() {
    if (indicator) {
        indicator.destroy();
        indicator = null;
    }
}
