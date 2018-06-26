# UCL Identity Federation

The UCL Identity Federation is the first way for unofficial applications to authenticate and gather information from UCL users. UCLIF supports OAuth 2.0 via the Authorization Code and Implicit grants and returns Bearer tokens whose payloads are signed JWTs.

The entire authentication flow is stateless in that UCLIF does not store cookies or other identifying information on the resource owner's device. Identifying tokens are instead passed inside the flow itself.

This application demonstrates how UCLIF can be integrated in a project using the `UCLIFAuth.py` library (contained herein) with the Authentication Code grant.
 
 To run this application, `config.sample.py` must be renamed to `config.py` and populated with an OAuth 2.0 Client ID and Client Secret.
 
 Interested parties should contact `inbox (at) philonas (dot) net` in order to acquire these. As part of your email you should include the name and function of your project to a reasonable degree of specificity and which OAuth 2.0 scopes you need (these can be found in `UCLIFAuth.py`), including for each a brief justification.
 
 Any other queries can be directed to the same email address.

# License
```text
BSD 3-Clause License

Copyright (c) 2018, Phil Demetriou
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```