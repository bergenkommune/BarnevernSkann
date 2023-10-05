# Copyright (C) 2023 Bergen Kommune
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from jwcrypto import jwk

key = jwk.JWK.generate(kty='RSA', size=2048, alg='RS256', use='sig', kid='Test')  # Insert your KID here
public_key = key.export_public()
private_key = key.export_private()
public_pem = pem = key.export_to_pem(private_key=False, password=None)
private_pem = key.export_to_pem(private_key=True, password=None)

with open('private_key.jwk', 'w') as f:
    f.write(str(private_key))

with open('public_key.jwk', 'w') as f:
    f.write(str(public_key))

with open('private_key.pem', 'w') as f:
    private_pem = str(private_pem).split('\\n')
    for line in private_pem:
        f.write(line)
        f.write('\n')

with open('public_key.pem', 'w') as f:
    public_pem = str(public_pem).split('\\n')
    for line in public_pem:
        f.write(line)
        f.write('\n')