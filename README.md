# Passport-Ubuntu #

[Passport](http://passportjs.org/) strategy for authenticating with [Ubuntu](https://login.ubuntu.com/) using OpenID.

## Install ##

`$ npm install --save passport-ubuntu`

## Example ##

    passport.use(new UbuntuStrategy({
      returnURL: 'https://example.com/auth/ubuntu/return',
      realm: 'https://example.com',
      stateless: true,
    },
    function(identifier, profile, done) {
      User.findOne({identifier: identifier}, function(err, user) {
        if (err) {
          done(err);
        }
        else {
          done(null, user);
        }
      });
    }));

    app.post('/auth/ubuntu', passport.authenticate('ubuntu'));
    app.get('/auth/ubuntu/return', passport.authenticate('ubuntu', {
      successRedirect: '/auth/me',
      failureRedirect: '/auth/login'
    }));

    app.get('/auth/login', function(req, res) {
      res.send('<form action="/auth/ubuntu" method="post"><div><input type="submit" value="Sign In"/></div></form>');
    });

    app.get('/auth/me', function(req, res) {
      res.send(req.user);
    });

    app.get('/auth/logout', function(req, res){
      req.logout();
      res.redirect('/');
    });

## License ##

Copyright (C) 2015 [Brian Douglass](http://bhdouglass.com/)

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published
by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranties of MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
