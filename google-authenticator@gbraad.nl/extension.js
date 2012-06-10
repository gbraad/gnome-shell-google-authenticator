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

const Main = imports.ui.main;
const MessageTray = imports.ui.messageTray;
const PanelMenu = imports.ui.panelMenu;
const PopupMenu = imports.ui.popupMenu;
//const Tweener = imports.ui.tweener;
const Extension = imports.misc.extensionUtils.getCurrentExtension();
const Totp = Extension.imports.totp;
const Convenience = Extension.imports.convenience;

let _settings;
//const SETTINGS_ACCOUNTS_KEY = 'accounts';
let _accounts;
let _defaultAccounts = [{
    "name": "alice@google.com",
    "secret": "JBSWY3DPEHPK3PXP"
}, {
    "name": "alice+again@google.com",
    "secret": "JBSWY3DPEHPK3PXP"
}];

const Indicator = new Lang.Class({
    Name: 'GoogleAuthenticator',
    Extends: PanelMenu.SystemStatusButton,

    _init: function () {
        this.parent("changes-prevent");
        this._parseSettings();

        // This should occur every second
        this._timeout = Mainloop.timeout_add_seconds(1, Lang.bind(this, function () {
            this._updateTimer()
            return true;
        }));
        this._updateTimer(true)
    },

    // Update the keys based on timer tick or forced
    _updateTimer: function (force) {
        // Should indicate the countdown time and only update when needed
        let epoch = Math.round(new Date().getTime() / 1000.0);
        let countDown = 30 - (epoch % 30);

        // If we need to update the OTP keys
        if (force || epoch % 30 == 0) {
            // Reset
            this.menu.removeAll();

            for (let i = 0; i < _accounts.length; i++) {
                let account = _accounts[i];
                let index = i; // have to store local?	
                let key = Totp.updateOtp(account.secret);

                let accountMenu = new PopupMenu.PopupMenuItem(account.name + "\n" + key);
                /*
			let delButton = new St.Bin({reactive: true,
	                          can_focus: true,
	                          x_fill: true,
	                          y_fill: false,
				  track_hover: true });
	                let delIcon = new St.Icon({icon_name: 'edit-delete',
				icon_type: St.IconType.SYMBOLIC,
				icon_size: Main.panel.actor.height * 0.8});
			delButton.set_child(delIcon);
			delButton.connect('button-press-event', Lang.bind(this, function() { this._delAccount(index); }));
	                accountMenu.addActor(delButton, {align: St.Align.END});
			*/
                this.menu.addMenuItem(accountMenu);
            }

            //this._menuElements();
        }
    },

    _menuElements: function () {
        // Need to find a convenient way to update only the elements itself
        let addMenu = new PopupMenu.PopupMenuItem("Settings");
        let addButton = new St.Bin({
            reactive: true,
            can_focus: true,
            x_fill: true,
            y_fill: false,
            track_hover: true
        });
        let addIcon = new St.Icon({
            icon_name: 'list-add',
            icon_type: St.IconType.SYMBOLIC,
            icon_size: Main.panel.actor.height * 0.8
        });
        addButton.set_child(addIcon);
        addButton.connect('button-press-event', Lang.bind(this, function () {
            this._addAccount();
        }));
        addMenu.addActor(addButton, {
            align: St.Align.END
        });
        this.menu.addMenuItem(addMenu);
    },

    _delAccount: function (index) {
        //_accounts.splice(index, 1);
        //_settings.set_strv(SETTINGS_ACCOUNTS_KEY, _accounts);
        this._updateTimer(true);
    },

    _addAccount: function () {},

    _parseSettings: function () {
        // TODO: deal with gsettings and keyring
        _acounts = null;
        _settings = Convenience.getSettings();
        try {
            // TODO: parse account information 
            //_accounts = _settings.get_string(SETTINGS_ACCOUNTS_KEY);
        } catch (e) {
            global.logError("Google Authenticator: Error reading configuration = " + e);
        } finally {
            if (!_accounts) {
                _accounts = _defaultAccounts;
                //_settings.set_strv(SETTINGS_ACCOUNTS_KEY, _accounts);
            }
        }
    }

});

let indicator;

function init(metadata) {
    //Convenience.initTranslations();
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
