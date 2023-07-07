const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

var hasilHitung = 0;
var jumlahAngka = 0;

main();

function question(question) {
  return new Promise((resolve) => {
    rl.question(question, (data) => {
      resolve(data);
    });
  });
}

async function main() {
  try {
    hasilHitung = 0;
    jumlahAngka = 0;
    console.log("---Kalkulator sederhana--");
    console.log("Pilih bangun datar:");
    console.log("1. Luas Segitiga");
    console.log("2. Volume Kubus");
    console.log("3. Volume Tabung");
    console.log("Pilih kalkaluasi perhitungan:");
    console.log("4. Hitung Aritmatika");
    console.log("5. Keluar");

    let answer = await question(`Pilihan: `);
    if (answer == "1") {
      console.log("Perhitungan luas segitiga");
      let alas = await question(`Masukan alas: `);
      let tinggi = await question(`Masukan tinggi: `);
      console.log("------------------");
      console.log("Luas Segitiga: " + luasSegitiga(alas, tinggi));
      console.log("------------------");
      main();
    } else if (answer == "2") {
      console.log("Perhitungan volume kubus");
      let sisi = await question(`Masukan sisi: `);
      console.log("------------------");
      console.log("Volume Kubus: " + volumeKubus(sisi));
      console.log("------------------");
      main();
    } else if (answer == "3") {
      console.log("Perhitungan volume tabung");
      let r = await question(`Masukan jari-jari: `);
      let t = await question(`Masukan tinggi: `);
      console.log("------------------");
      console.log("Volume Tabung: " + volumeTabung(r, t));
      console.log("------------------");
      main();
    } else if (answer == "4") {
      console.log("Perhitungan arimatika");
      hitungAritmatik();
    } else if (answer == "5") {
      rl.close();
    } else {
      console.log("Pilihan anda tidak ada");
      rl.close();
    }
  } catch (err) {
    console.log(err);
    rl.close;
  }
}

function luasSegitiga(a, t) {
  let luas;

  luas = 0.5 * a * t;
  return luas;
}

function volumeKubus(s) {
  let volume;

  volume = s * s * s;
  return volume;
}

function volumeTabung(r, t) {
  let volume;
  let phi = 3.14;

  volume = phi * (r * r) * t;

  return volume;
}

async function hitungAritmatik() {
  if (jumlahAngka == 0) {
    console.log("------------------");
    let angka = await question(`Masukan angka: `);
    jumlahAngka++;
    console.log("1. +");
    console.log("2. -");
    console.log("3. x");
    console.log("4. ÷");
    console.log("5. Akar");
    console.log("6. Kuadrat");
    console.log("7. Pangkat");
    console.log("8. Selesai");
    console.log("9. Kembali");
    rl.question("Pilihan: ", (pilihan) => {
      if (pilihan == "1") {
        tambah(angka);
      } else if (pilihan == "2") {
        kurang(angka);
      } else if (pilihan == "3") {
        kali(angka);
      } else if (pilihan == "4") {
        bagi(angka);
      } else if (pilihan == "5") {
        akar(angka);
      } else if (pilihan == "6") {
        kuadrat(angka);
      } else if (pilihan == "7") {
        pangkat(angka);
      } else if (pilihan == "8") {
        rl.close();
      } else if (pilihan == "9") {
        main();
      } else {
        console.log("Pilihan tidak ada");
      }
    });
  } else {
    console.log("------------------");
    console.log("1. +");
    console.log("2. -");
    console.log("3. x");
    console.log("4. ÷");
    console.log("5. Akar");
    console.log("6. Kuadrat");
    console.log("7. Pangkat");
    console.log("8. Selesai");
    console.log("9. Kembali");

    let pilihan = await question(`Masukan Pilihan: `);
    if (pilihan == "1") {
      tambah(hasilHitung);
    } else if (pilihan == "2") {
      kurang(hasilHitung);
    } else if (pilihan == "3") {
      kali(hasilHitung);
    } else if (pilihan == "4") {
      bagi(hasilHitung);
    } else if (pilihan == "5") {
      akar(hasilHitung);
    } else if (pilihan == "6") {
      kuadrat(hasilHitung);
    } else if (pilihan == "7") {
      pangkat(hasilHitung);
    } else if (pilihan == "8") {
      console.log(`Hasil akhir = ${hasilHitung}`);
      rl.close();
    } else if (pilihan == "9") {
      console.log(`Hasil akhir = ${hasilHitung}`);
      main();
    } else {
      console.log("Pilihan tidak ada");
    }
  }
}

function tambah(angka) {
  rl.question("Masukan angka kedua: ", (angkaKedua) => {
    hasilHitung = Number(angka) + Number(angkaKedua);
    console.log("------------------");
    console.log(`Hasil Akhir = ${hasilHitung}`);
    hitungAritmatik();
  });
}

function kurang(angka) {
  rl.question("Masukan angka kedua: ", (angkaKedua) => {
    hasilHitung = Number(angka) - Number(angkaKedua);
    console.log("------------------");
    console.log(`Hasil Akhir = ${hasilHitung}`);
    hitungAritmatik();
  });
}

function kali(angka) {
  rl.question("Masukan angka kedua: ", (angkaKedua) => {
    hasilHitung = Number(angka) * Number(angkaKedua);
    console.log("------------------");
    console.log(`Hasil Akhir = ${hasilHitung}`);
    hitungAritmatik();
  });
}

function bagi(angka) {
  rl.question("Masukan angka kedua: ", (angkaKedua) => {
    hasilHitung = Number(angka) / Number(angkaKedua);
    console.log("------------------");
    console.log(`Hasil Akhir = ${hasilHitung}`);
    hitungAritmatik();
  });
}

function akar(angka) {
  hasilHitung = Math.sqrt(Number(angka));
  console.log("------------------");
  console.log(`Hasil Akhir = ${hasilHitung}`);
  hitungAritmatik();
}

function kuadrat(angka) {
  hasilHitung = Number(angka) * Number(angka);
  console.log("------------------");
  console.log(`Hasil Akhir = ${hasilHitung}`);
  hitungAritmatik();
}

function pangkat(angka) {
  rl.question("Masukan pangkat: ", (angkaKedua) => {
    hasilHitung = Number(angka) ** Number(angkaKedua);
    console.log("------------------");
    console.log(`Hasil Akhir = ${hasilHitung}`);
    hitungAritmatik();
  });
}
