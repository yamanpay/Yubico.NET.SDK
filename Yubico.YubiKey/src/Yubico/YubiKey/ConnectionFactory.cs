﻿// Copyright 2024 Yubico AB
// 
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Threading;
using Microsoft.Extensions.Logging;
using Yubico.Core.Devices.Hid;
using Yubico.Core.Devices.SmartCard;
using Yubico.YubiKey.Scp;

namespace Yubico.YubiKey
{
    // TODO Consider merging with ConnectionManager
    public class ConnectionFactory
    {
        private readonly ILogger _log;
        private readonly YubiKeyDevice _device;
        private readonly ISmartCardDevice? _smartCardDevice;
        private readonly IHidDevice? _hidKeyboardDevice;
        private readonly IHidDevice? _hidFidoDevice;

        public ConnectionFactory(
            ILogger log,
            YubiKeyDevice device,
            ISmartCardDevice? smartCardDevice,
            IHidDevice? hidKeyboardDevice,
            IHidDevice? hidFidoDevice)
        {
            _log = log;
            _device = device;
            _smartCardDevice = smartCardDevice;
            _hidKeyboardDevice = hidKeyboardDevice;
            _hidFidoDevice = hidFidoDevice;
        }

        [Obsolete("Obsolete")]
        internal IScp03YubiKeyConnection CreateScpConnection(YubiKeyApplication application, Yubico.YubiKey.Scp03.StaticKeys scp03Keys)
        {

            if (_smartCardDevice is null)
            {
                string errorMessage = "No smart card interface present. Unable to establish SCP connection to YubiKey."; // TODO Reusable error messaGE
                throw new InvalidOperationException(errorMessage);
            }

            _log.LogInformation("Connecting via the SmartCard interface using SCP03.");
            WaitForReclaimTimeout(Transport.SmartCard);

            return new Scp03Connection(_smartCardDevice, application, scp03Keys);
        }

        /// <summary>
        /// Creates a connection to the YubiKey for a specific application using SCP.
        /// </summary>
        /// <param name="application">The application to connect to.</param>
        /// <param name="keyParameters">The parameters for the SCP connection.</param>
        /// <returns>The connection to the YubiKey, or null if unable to connect.</returns>
        /// <exception cref="InvalidOperationException">Thrown if no suitable interface is present.</exception>
        public IScpYubiKeyConnection CreateScpConnection(YubiKeyApplication application, ScpKeyParameters keyParameters)
        {
            LogConnectionAttempt(application, keyParameters);

            if (_smartCardDevice is null)
            {
                string errorMessage = "No smart card interface present. Unable to establish SCP connection to YubiKey.";
                throw new InvalidOperationException(errorMessage);
            }

            _log.LogInformation("Connecting via the SmartCard interface using SCP03.");
            WaitForReclaimTimeout(Transport.SmartCard);

            return new ScpConnection(_smartCardDevice, application, keyParameters);
        }

        /// <summary>
        /// Creates a connection to the YubiKey for a specific application that doesn't use the SmartCard interface (i.e. not SCP03).
        /// </summary>
        /// <param name="application">The application to connect to.</param>
        /// <returns>The connection to the YubiKey, or null if unable to connect.</returns>
        /// <exception cref="InvalidOperationException">Thrown if no suitable interface is present.</exception>
        public IYubiKeyConnection CreateConnection(YubiKeyApplication application)
        {
            if (_smartCardDevice != null)
            {
                _log.LogInformation("Connecting via the SmartCard interface.");
                
                WaitForReclaimTimeout(Transport.SmartCard);
                return new SmartCardConnection(_smartCardDevice, application);
            }

            if (_hidKeyboardDevice != null && application == YubiKeyApplication.Otp)
            {
                _log.LogInformation("Connecting via the Keyboard interface.");
                
                WaitForReclaimTimeout(Transport.HidKeyboard);
                return new KeyboardConnection(_hidKeyboardDevice);
            }

            if (_hidFidoDevice != null && (application == YubiKeyApplication.Fido2 || application == YubiKeyApplication.FidoU2f))
            {
                _log.LogInformation("Connecting via the FIDO interface.");
                
                WaitForReclaimTimeout(Transport.HidFido);
                return new FidoConnection(_hidFidoDevice);
            }

            string errorMessage = "No suitable interface present. Unable to establish connection to YubiKey.";
            throw new InvalidOperationException(errorMessage);
        }

        // This function handles waiting for the reclaim timeout on the YubiKey to elapse. The reclaim timeout requires
        // the SDK to wait 3 seconds since the last USB message to an interface before switching to a different interface.
        // Failure to wait can result in very strange behavior from the USB devices ultimately resulting in communication
        // failures (i.e. exceptions).
        private void WaitForReclaimTimeout(Transport newTransport)
        {
            // Newer YubiKeys are able to switch interfaces much, much faster. Maybe this is being paranoid, but we
            // should still probably wait a few milliseconds for things to stabilize. But definitely not the full
            // three seconds! For older keys, we use a value of 3.01 seconds to give us a little wiggle room as the
            // YubiKey's measurement for the reclaim timeout is likely not as accurate as our system clock.
            var reclaimTimeout = CanFastReclaim()
                ? TimeSpan.FromMilliseconds(100)
                : TimeSpan.FromSeconds(3.01);

            // We're only affected by the reclaim timeout if we're switching USB transports.
            if (_device.LastActiveTransport == newTransport)
            {
                _log.LogInformation(
                    "{Transport} transport is already active. No need to wait for reclaim.",
                    _device.LastActiveTransport);

                return;
            }

            _log.LogInformation(
                "Switching USB transports from {OldTransport} to {NewTransport}.",
                _device.LastActiveTransport,
                newTransport);

            var timeSinceLastActivation = DateTime.Now - GetLastActiveTime();

            // If we haven't already waited the duration of the reclaim timeout, we need to do so.
            // Otherwise, we've already waited and can immediately switch the transport.
            if (timeSinceLastActivation < reclaimTimeout)
            {
                var waitNeeded = reclaimTimeout - timeSinceLastActivation;

                _log.LogInformation(
                    "Reclaim timeout still active. Need to wait {TimeMS} milliseconds.",
                    waitNeeded.TotalMilliseconds);

                Thread.Sleep(waitNeeded);
            }

            _device.LastActiveTransport = newTransport;

            _log.LogInformation("Reclaim timeout has lapsed. It is safe to switch USB transports.");
        }

        private bool CanFastReclaim()
        {
            if (AppContext.TryGetSwitch(YubiKeyCompatSwitches.UseOldReclaimTimeoutBehavior, out bool useOldBehavior) &&
                useOldBehavior)
            {
                return false;
            }

            return _device.HasFeature(YubiKeyFeature.FastUsbReclaim);
        }

        private DateTime GetLastActiveTime() =>
            _device.LastActiveTransport switch
            {
                Transport.SmartCard when _smartCardDevice is { } => _smartCardDevice.LastAccessed,
                Transport.HidFido when _hidFidoDevice is { } => _hidFidoDevice.LastAccessed,
                Transport.HidKeyboard when _hidKeyboardDevice is { } => _hidKeyboardDevice.LastAccessed,
                Transport.None => DateTime.Now,
                _ => throw new InvalidOperationException(ExceptionMessages.DeviceTypeNotRecognized)
            };

        private void LogConnectionAttempt(
            YubiKeyApplication application,
            ScpKeyParameters keyParameters)
        {
            string applicationName = GetApplicationName(application);
            string scpInfo = keyParameters switch
            {
                Scp03KeyParameters scp03KeyParameters => $"SCP03 ({scp03KeyParameters.KeyReference})",
                Scp11KeyParameters scp11KeyParameters => $"SCP11 ({scp11KeyParameters.KeyReference})",
                _ => "Unknown"
            };

            _log.LogInformation("YubiKey connecting to {Application} application over {ScpInfo}", applicationName, scpInfo);
        }

        private static string GetApplicationName(YubiKeyApplication application) =>
            Enum.GetName(typeof(YubiKeyApplication), application) ?? "Unknown";
    }
}
