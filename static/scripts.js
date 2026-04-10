
document.addEventListener("DOMContentLoaded", function () {


    if (typeof chartDataRaw !== "undefined") {

        const canvas = document.getElementById("attackChart");

        if (canvas) {

            const ctx = canvas.getContext("2d");

            new Chart(ctx, {
                type: "doughnut",

                data: {
                    labels: Object.keys(chartDataRaw),

                    datasets: [{
                        data: Object.values(chartDataRaw),

                        backgroundColor: [
                            "#800000",
                            "#26a69a",
                            "#ff3333",
                            "#004d40",
                            "#b0bec5",
                            "#4d0000"
                        ],

                        borderColor: "#050505",
                        borderWidth: 2
                    }]
                },

                options: {
                    responsive: true,
                    maintainAspectRatio: false,

                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                color: "#b0bec5",
                                font: { size: 10 }
                            }
                        }
                    }
                }
            });

        }

    }




    const rows = document.querySelectorAll(".tech-row");

    rows.forEach(row => {

        row.addEventListener("click", function(){

            const name = this.dataset.name;
            const id = this.dataset.id;
            const phase = this.dataset.phase;
            const platforms = this.dataset.platforms;
            const desc = this.dataset.desc;

            showDetails(name, id, phase, platforms, desc);

        });

    });

});




function downloadDashboard() {

    const element = document.getElementById("report-content");

    if (!element) return;

    html2pdf()
        .from(element)
        .set({
            margin: 0.5,
            filename: `${threatName}_Dashboard.pdf`,
            html2canvas: {
                scale: 2,
                backgroundColor: "#050505"
            },
            jsPDF: {
                orientation: "landscape"
            }
        })
        .save();

}




function openCatalog() {

    const modal = document.getElementById("catalogModal");

    if (modal) modal.style.display = "block";

}

function closeCatalog() {

    const modal = document.getElementById("catalogModal");

    if (modal) modal.style.display = "none";

}

function selectMalware(name) {

    const input = document.getElementById("malwareInput");

    if (input) input.value = name;

    closeCatalog();

}




function openGlossary() {

    const modal = document.getElementById("glossaryModal");

    if (modal) modal.style.display = "block";

}

function closeGlossary() {

    const modal = document.getElementById("glossaryModal");

    if (modal) modal.style.display = "none";

}




function showDetails(name, id, phase, platforms, desc) {

    const modal = document.getElementById("detailsModal");

    if (!modal) return;

    document.getElementById("modalTitle").textContent = name;
    document.getElementById("modalID").textContent = id;
    document.getElementById("modalPhase").textContent = phase;
    document.getElementById("modalPlatforms").textContent = platforms;
    document.getElementById("modalDesc").textContent = desc;

    modal.style.display = "block";

}

function closeDetails() {

    const modal = document.getElementById("detailsModal");

    if (modal) modal.style.display = "none";

}




window.onclick = function (event) {

    if (event.target.classList.contains("modal")) {

        closeCatalog();
        closeGlossary();
        closeDetails();

    }

};




document.addEventListener("keydown", function(e){

    if (e.key === "Escape") {

        closeCatalog();
        closeGlossary();
        closeDetails();

    }

});
