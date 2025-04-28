// Global variables
let capturing = false;
let totalPackets = 0;
let totalAttacks = 0;
let pollingInterval = null;

// Fetch available network interfaces
async function fetchNetworks() {
    try {
        const response = await axios.get('/networks');
        const interfaces = response.data;
        const select = document.getElementById("networks");

        // Clear any existing options
        select.innerHTML = '';

        interfaces.forEach(intf => {
            const option = document.createElement("option");
            option.value = intf;
            option.textContent = intf;
            select.appendChild(option);
        });
    } catch (error) {
        console.error("Error fetching network interfaces: ", error);
        alert("Failed to load network interfaces.");
    }
}

// Start capturing packets
async function startCapture() {
    const networkInterface = document.getElementById("networks").value;
    if (!networkInterface) {
        alert("Please select a network interface.");
        return;
    }

    capturing = true;
    try {
        const startButton = document.querySelector(".btn");
        const stopButton = document.querySelector(".btn-stop");

        // Disable the start button and enable the stop button
        startButton.disabled = true;
        startButton.classList.add("disabled");
        stopButton.disabled = false;
        stopButton.classList.remove("disabled");

        const response = await axios.post('/start_capture', { interface: networkInterface });
        alert(response.data.status);

        // Clear existing data
        document.getElementById("alertList").innerHTML = "";
        document.getElementById("totalPackets").textContent = "0";
        document.getElementById("totalAttacks").textContent = "0";

        // Initialize the feature container as a table
        initializeFeatureTable();

        totalPackets = 0;
        totalAttacks = 0;

        // Start polling for new packet data every 3 seconds (adjusted from 30 seconds for better responsiveness)
        fetchPackets(); // Initial fetch
        pollingInterval = setInterval(fetchPackets, 3000);
    } catch (error) {
        console.error("Error starting capture: ", error);
        alert("Failed to start capture: " + (error.response?.data?.message || error.message));
    }
}

// Stop capturing packets
async function stopCapture() {
    capturing = false;
    // Clear the polling interval
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }

    try {
        const startButton = document.querySelector(".btn");
        const stopButton = document.querySelector(".btn-stop");

        // Disable the stop button and enable the start button
        stopButton.disabled = true;
        stopButton.classList.add("disabled");
        startButton.disabled = false;
        startButton.classList.remove("disabled");

        const response = await axios.post('/stop_capture');
        alert(response.data.status);
    } catch (error) {
        console.error("Error stopping capture: ", error);
        alert("Failed to stop capture: " + (error.response?.data?.message || error.message));
    }
}

// Initialize the feature container with a table
function initializeFeatureTable() {
    const featureContainer = document.getElementById("featureContainer");
    featureContainer.innerHTML = `
        <table id="featureTable" class="feature-table">
            <thead>
                <tr>
                    <th>Flow Duration</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Destination Port</th>
                    <th>Protocol</th>
                    <th>Prediction</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody id="featureTableBody">
                <!-- Feature rows will be added here -->
            </tbody>
        </table>
    `;
}

// Fetch packets and update the UI
async function fetchPackets() {
    if (!capturing) return;

    try {
        const response = await axios.get('/get_packets');
        const packets = response.data.packets;

        if (packets && packets.length > 0) {
            // Get the feature table body
            const featureTableBody = document.getElementById("featureTableBody");

            // Clear existing content if this is the first fetch
            if (totalPackets === 0) {
                featureTableBody.innerHTML = '';
            }

            // Add new packets to the feature table
            packets.forEach(packet => {
                // Check if this packet is already in the table (avoid duplicates)
                const packetKey = `${packet.source}-${packet.destination}-${packet.destination_port}-${packet.flow_duration}`;
                if (document.querySelector(`[data-packet-key="${packetKey}"]`)) {
                    return; // Skip if already displayed
                }

                // Format the flow duration to be more readable
                const formattedDuration = parseFloat(packet.flow_duration).toFixed(2);

                // Add feature row
                const featureRow = document.createElement("tr");
                featureRow.setAttribute('data-packet-key', packetKey);
                featureRow.innerHTML = `
                    <td>${formattedDuration}</td>
                    <td>${packet.source}</td>
                    <td>${packet.destination}</td>
                    <td>${packet.destination_port}</td>
                    <td>${packet.protocol || 'N/A'}</td>
                    <td>${packet.prediction}</td>
                    <td>
                        <button class="btn-details" onclick="toggleDetails(this)" data-details='${JSON.stringify(packet.features)}'>
                            Show Details
                        </button>
                    </td>
                `;

                // Highlight rows for detected attacks
                if (packet.prediction !== "Benign") {
                    featureRow.style.backgroundColor = "#fff0f0";
                    featureRow.style.fontWeight = "bold";
                }

                // Add row at the top of the table
                featureTableBody.insertBefore(featureRow, featureTableBody.firstChild);

                // Add alerts for detected attacks
                if (packet.prediction !== "Benign") {
                    addAlertEntry(packet);
                    totalAttacks++;
                }

                totalPackets++;
            });

            // Limit the number of rows to prevent the table from getting too large
            while (featureTableBody.children.length > 50) {
                featureTableBody.removeChild(featureTableBody.lastChild);
            }

            // Update stats
            document.getElementById("totalPackets").textContent = totalPackets;
            document.getElementById("totalAttacks").textContent = totalAttacks;
        }
    } catch (error) {
        console.error("Error fetching packets: ", error);
    }
}

// Toggle showing detailed features
function toggleDetails(button) {
    try {
        const details = JSON.parse(button.getAttribute('data-details'));
        const parentRow = button.parentNode.parentNode;

        // Check if details row already exists
        const nextRow = parentRow.nextSibling;
        if (nextRow && nextRow.classList && nextRow.classList.contains('details-row')) {
            // Remove details row if it exists
            nextRow.parentNode.removeChild(nextRow);
            button.textContent = 'Show Details';
        } else {
            // Create new details row
            const detailsRow = document.createElement('tr');
            detailsRow.className = 'details-row';

            // Create details cell that spans all columns
            const detailsCell = document.createElement('td');
            detailsCell.colSpan = 7;

            // Create a table for the details
            let detailsHTML = '<table class="details-table">';
            for (const [key, value] of Object.entries(details)) {
                // Format the value for better readability
                let displayValue = value;
                if (typeof value === 'number') {
                    displayValue = parseFloat(value).toFixed(6);
                }
                detailsHTML += `<tr><th>${key}</th><td>${displayValue}</td></tr>`;
            }
            detailsHTML += '</table>';

            detailsCell.innerHTML = detailsHTML;
            detailsRow.appendChild(detailsCell);

            // Insert after the current row
            if (parentRow.nextSibling) {
                parentRow.parentNode.insertBefore(detailsRow, parentRow.nextSibling);
            } else {
                parentRow.parentNode.appendChild(detailsRow);
            }

            button.textContent = 'Hide Details';
        }
    } catch (error) {
        console.error("Error toggling details: ", error);
        alert("Error displaying details");
    }
}

// Add an alert entry for detected attacks
function addAlertEntry(packet) {
    const alertList = document.getElementById("alertList");
    const alertItem = document.createElement("li");
    const timestamp = packet.time || new Date().toLocaleTimeString();

    alertItem.textContent = `🚨 Detected ${packet.prediction} attack from ${packet.source} to ${packet.destination} at ${timestamp}`;

    // Add a class for styling
    alertItem.className = "alert-item";

    // Add the alert to the top of the list
    alertList.insertBefore(alertItem, alertList.firstChild);

    // Limit the number of alerts shown
    while (alertList.children.length > 20) {
        alertList.removeChild(alertList.lastChild);
    }
}

// Function to filter features in the table
function filterFeatures() {
    const searchValue = document.getElementById("featureSearch").value.toLowerCase();
    const tableBody = document.getElementById("featureTableBody");
    const rows = tableBody.getElementsByTagName("tr");

    // Loop through rows and hide those that do not match the search
    for (const row of rows) {
        const rowText = row.textContent.toLowerCase();
        if (rowText.includes(searchValue)) {
            row.style.display = ""; // Show row if it matches the search
        } else {
            row.style.display = "none"; // Hide row if it doesn't match
        }
    }
}

// Fetch networks on page load
window.onload = fetchNetworks;